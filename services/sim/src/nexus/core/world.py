"""World model, canonical encoding, `state_hash` and snapshots (SIM-CORE SC-4, SC-9, SC-14, §4, §5).

Systems reach entities only through `World` (Q-SIM-4), never its storage. `Entity` holds only the
fields the first systems need; every other SIM-CORE §4 field is added by the system that first
uses it.

One walker, `to_canonical`, turns a world into plain sorted data. Snapshots keep floats exactly
(float64), so a restored run continues bit-identically; only `state_hash` quantizes (ADR-0002):
positions to integer mm, velocities to integer mm/s. ADR-0002's 1e-6 step applies when the first
other float field arrives. Python's `round` is round-half-to-even on the exact float value, so it
is deterministic. The RNG state is world state, so snapshots and the hash cover it.
"""

import hashlib
import math
from collections.abc import Iterator
from dataclasses import dataclass, fields
from typing import Annotated, Any, Self, cast, get_args, get_origin

import msgpack

from nexus.contracts.gen.common.enums import OwnerKind, Side, UnitKind
from nexus.core.rng import SimRng

FORMAT_VERSION = 1
_MM = 1000.0  # metres -> millimetres; m/s -> mm/s
_MAX_ABS = 1e9  # m or m/s; keeps mm quantization well inside int64
_WORLD_KEYS = ("campaign", "entities", "next_entity_id", "next_event_seq", "rng", "v")


def _literal_values(alias: Any) -> tuple[str, ...]:
    """The allowed strings of a generated `type X = Literal[...]` (optionally Annotated)."""
    value = alias.__value__
    if get_origin(value) is Annotated:
        value = get_args(value)[0]
    return get_args(value)


_UNIT_KINDS = _literal_values(UnitKind)
_SIDES = _literal_values(Side)
_OWNER_KINDS = _literal_values(OwnerKind)


@dataclass(frozen=True, slots=True)
class Vec2:
    """A point or vector in metres (or m/s), float64. Ints are stored as floats."""

    x: float
    y: float

    def __post_init__(self) -> None:
        for name in ("x", "y"):
            v = getattr(self, name)
            number = isinstance(v, int | float) and not isinstance(v, bool)
            if not (number and math.isfinite(v) and abs(v) <= _MAX_ABS):
                raise ValueError(f"Vec2.{name} must be finite with |v| <= {_MAX_ABS:g}, got {v!r}")
            object.__setattr__(self, name, float(v))


_ZERO = Vec2(0.0, 0.0)


@dataclass(slots=True)
class Entity:
    """A unit or facility. `id` is allocated by `World.spawn` and must not change."""

    id: int
    kind: UnitKind
    side: Side
    owner_kind: OwnerKind
    commander_id: str | None
    callsign: str | None
    pos: Vec2
    vel: Vec2  # m/s
    hp: int


@dataclass(slots=True)
class Campaign:
    id: str  # CampaignId
    seed: int
    config_hash: str
    tick: int = 0
    clock_paused: bool = False


_ENTITY_KEYS = tuple(f.name for f in fields(Entity))
_CAMPAIGN_KEYS = tuple(f.name for f in fields(Campaign))


class World:
    """The whole sim state. Entity ids start at 1 and are never reused (SC-4).

    `_entities` is insertion-ordered by id: ids are allocated monotonically and only ever removed,
    so iterating the dict is id order without sorting (`load` checks the same for snapshots).
    """

    __slots__ = ("_entities", "_next_entity_id", "_next_event_seq", "campaign", "rng")

    def __init__(self, campaign: Campaign, rng: SimRng) -> None:
        self.campaign = campaign
        self.rng = rng
        self._entities: dict[int, Entity] = {}
        self._next_entity_id = 1
        self._next_event_seq = 1

    @classmethod
    def new(cls, campaign: Campaign) -> Self:
        return cls(campaign, SimRng(campaign.seed))

    def spawn(
        self,
        kind: UnitKind,
        side: Side,
        owner_kind: OwnerKind,
        pos: Vec2,
        *,
        commander_id: str | None = None,
        callsign: str | None = None,
        vel: Vec2 = _ZERO,
        hp: int,
    ) -> Entity:
        entity = Entity(
            self._next_entity_id, kind, side, owner_kind, commander_id, callsign, pos, vel, hp
        )
        self._entities[entity.id] = entity
        self._next_entity_id += 1
        return entity

    def get(self, entity_id: int) -> Entity:
        return self._entities[entity_id]

    def remove(self, entity_id: int) -> None:
        del self._entities[entity_id]

    def entities(self) -> Iterator[Entity]:
        """All entities in ascending id order (SC-4). Do not spawn or remove while iterating."""
        return iter(self._entities.values())

    def next_event_seq(self) -> int:
        """The next campaign-wide `event_seq` (SC-14), starting at 1."""
        seq = self._next_event_seq
        self._next_event_seq += 1
        return seq

    def __len__(self) -> int:
        return len(self._entities)


def _xy(v: Vec2, quantize: bool) -> list[Any]:
    return [round(v.x * _MM), round(v.y * _MM)] if quantize else [v.x, v.y]


def _entity_data(e: Entity, quantize: bool) -> dict[str, Any]:
    return {
        "callsign": e.callsign,
        "commander_id": e.commander_id,
        "hp": e.hp,
        "id": e.id,
        "kind": e.kind,
        "owner_kind": e.owner_kind,
        "pos": _xy(e.pos, quantize),
        "side": e.side,
        "vel": _xy(e.vel, quantize),
    }


def to_canonical(world: World, *, quantize: bool) -> dict[str, Any]:
    """Plain data with sorted keys and entities in id order; quantized for the hash only."""
    c = world.campaign
    return {
        "campaign": {
            "clock_paused": c.clock_paused,
            "config_hash": c.config_hash,
            "id": c.id,
            "seed": c.seed,
            "tick": c.tick,
        },
        "entities": [_entity_data(e, quantize) for e in world.entities()],
        "next_entity_id": world._next_entity_id,
        "next_event_seq": world._next_event_seq,
        "rng": {name: dict(sorted(s.items())) for name, s in world.rng.to_state().items()},
        "v": FORMAT_VERSION,
    }


def state_hash(world: World) -> str:
    """Hex blake2b-256 of the quantized canonical msgpack (SIM-CORE §5)."""
    packed = msgpack.packb(to_canonical(world, quantize=True), use_bin_type=True)
    return hashlib.blake2b(packed, digest_size=32).hexdigest()


def save(world: World) -> bytes:
    """Lossless snapshot bytes (SC-9). Compression and the file header are NX-103."""
    return cast(bytes, msgpack.packb(to_canonical(world, quantize=False), use_bin_type=True))


# --- load: every value is checked; anything unexpected is a ValueError. ---


def _fields(value: object, keys: tuple[str, ...], what: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{what} must have exactly the keys {list(keys)}")
    return value


def _int(value: object, what: str, lo: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < lo:
        raise ValueError(f"{what} must be an int >= {lo}, got {value!r}")
    return value


def _str(value: object, what: str, allowed: tuple[str, ...] = (), *, optional: bool = False) -> Any:
    """A string (one of `allowed` when given), or None when `optional`."""
    if (optional and value is None) or (isinstance(value, str) and value in (allowed or (value,))):
        return value
    raise ValueError(f"bad {what}: {value!r}")


def _vec(value: object, what: str) -> Vec2:
    if not isinstance(value, list) or len(value) != 2:
        raise ValueError(f"{what} must be [x, y]")
    return Vec2(value[0], value[1])


def _load_entity(value: object) -> Entity:
    d = _fields(value, _ENTITY_KEYS, "entity")
    return Entity(
        id=_int(d["id"], "entity id", 1),
        kind=_str(d["kind"], "kind", _UNIT_KINDS),
        side=_str(d["side"], "side", _SIDES),
        owner_kind=_str(d["owner_kind"], "owner_kind", _OWNER_KINDS),
        commander_id=_str(d["commander_id"], "commander_id", optional=True),
        callsign=_str(d["callsign"], "callsign", optional=True),
        pos=_vec(d["pos"], "pos"),
        vel=_vec(d["vel"], "vel"),
        hp=_int(d["hp"], "hp"),
    )


def _load_campaign(value: object) -> Campaign:
    d = _fields(value, _CAMPAIGN_KEYS, "campaign")
    if not isinstance(d["clock_paused"], bool):
        raise ValueError("clock_paused must be a bool")
    return Campaign(
        id=_str(d["id"], "campaign id"),
        seed=_int(d["seed"], "seed"),
        config_hash=_str(d["config_hash"], "config_hash"),
        tick=_int(d["tick"], "tick"),
        clock_paused=d["clock_paused"],
    )


def load(data: bytes) -> World:
    """Rebuild a world from `save` output; the run continues exactly as before."""
    d = _fields(msgpack.unpackb(data, raw=False), _WORLD_KEYS, "snapshot")
    if _int(d["v"], "format version") != FORMAT_VERSION:
        raise ValueError(f"unsupported snapshot format version {d['v']}")
    world = World(_load_campaign(d["campaign"]), SimRng.from_state(d["rng"]))
    world._next_entity_id = _int(d["next_entity_id"], "next_entity_id", 1)
    world._next_event_seq = _int(d["next_event_seq"], "next_event_seq", 1)
    if not isinstance(d["entities"], list):
        raise ValueError("entities must be a list")
    last_id = 0
    for raw in d["entities"]:
        entity = _load_entity(raw)
        if not last_id < entity.id < world._next_entity_id:
            raise ValueError("entity ids must ascend and stay below next_entity_id")
        last_id = entity.id
        world._entities[entity.id] = entity
    return world
