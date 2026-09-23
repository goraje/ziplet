"""A :mod:`pathlib`-style interface for ZIP archives.

:class:`Path` mirrors CPython 3.14's ``zipfile.Path``: it accepts either an
already-open :class:`~ziplet.zipfile.file.ZipFile` or an archive filename, and
lets callers navigate, read, and glob archive members using familiar
``pathlib.Path``-like semantics, including implied (unlisted) directory
entries.

Adapted from CPython's ``zipfile._path`` package.
"""

from __future__ import annotations

import contextlib
import io
import itertools
import pathlib
import posixpath
import re
import stat
from collections.abc import Iterable, Iterator
from typing import IO, Any, cast

from ziplet.zipfile.file import ZipFile
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.path.glob import Translator
from ziplet.zipfile.shared import ReadWriteMode, StrPath

__all__ = ["Path"]


def _parents(path: str) -> Iterator[str]:
    """Generate all parent segments of *path* (excluding *path* itself).

    >>> list(_parents('b/d'))
    ['b']
    >>> list(_parents('/b/d/'))
    ['/b']
    >>> list(_parents('b/d/f/'))
    ['b/d', 'b']
    >>> list(_parents('b'))
    []
    >>> list(_parents(''))
    []
    """
    return itertools.islice(_ancestry(path), 1, None)


def _ancestry(path: str) -> Iterator[str]:
    """Generate all ancestor segments of *path*, including *path* itself.

    >>> list(_ancestry('b/d'))
    ['b/d', 'b']
    >>> list(_ancestry('/b/d/'))
    ['/b/d', '/b']
    >>> list(_ancestry('b/d/f/'))
    ['b/d/f', 'b/d', 'b']
    >>> list(_ancestry('b'))
    ['b']
    >>> list(_ancestry(''))
    []

    Multiple separators are treated like a single one.

    >>> list(_ancestry('//b//d///f//'))
    ['//b//d///f', '//b//d', '//b']
    """
    path = path.rstrip(posixpath.sep)
    while path.rstrip(posixpath.sep):
        yield path
        path, _tail = posixpath.split(path)


def _dedupe(iterable: Iterable[str]) -> Iterable[str]:
    """Deduplicate *iterable*, preserving original order."""
    return dict.fromkeys(iterable)


def _difference(minuend: Iterable[str], subtrahend: Iterable[str]) -> Iterator[str]:
    """Yield items from *minuend* that are not present in *subtrahend*.

    Retains order with O(1) membership lookup.
    """
    return itertools.filterfalse(set(subtrahend).__contains__, minuend)


class CompleteDirs(ZipFile):
    """A :class:`~ziplet.zipfile.file.ZipFile` that always lists implied dirs.

    ZIP archives frequently omit explicit directory entries; a member such as
    ``foo/bar.txt`` implies a ``foo/`` directory even when no entry for
    ``foo/`` exists in the archive. :class:`CompleteDirs` synthesizes those
    implied directory names so :class:`Path` navigation and iteration behave
    consistently regardless of whether directory entries were written.

    >>> list(CompleteDirs._implied_dirs(['foo/bar.txt', 'foo/bar/baz.txt']))
    ['foo/', 'foo/bar/']
    >>> list(CompleteDirs._implied_dirs(['foo/bar.txt', 'foo/bar/baz.txt', 'foo/bar/']))
    ['foo/']
    """

    @staticmethod
    def _implied_dirs(names: Iterable[str]) -> Iterable[str]:
        parents = itertools.chain.from_iterable(map(_parents, names))
        as_dirs = (p + posixpath.sep for p in parents)
        return _dedupe(_difference(as_dirs, names))

    def namelist(self) -> list[str]:
        """Return archive member names, including synthesized implied dirs."""
        names = super().namelist()
        return names + list(self._implied_dirs(names))

    def _name_set(self) -> set[str]:
        return set(self.namelist())

    def resolve_dir(self, name: str) -> str:
        """Return *name* with a trailing slash if it names an implied directory."""
        names = self._name_set()
        dirname = name + "/"
        dir_match = name not in names and dirname in names
        return dirname if dir_match else name

    def getinfo(self, name: str) -> ZipInfo:
        """Return :class:`ZipInfo` for *name*, synthesizing implied dirs."""
        try:
            return super().getinfo(name)
        except KeyError:
            if not name.endswith("/") or name not in self._name_set():
                raise
            return ZipInfo(filename=name)

    @classmethod
    def make(cls, source: ZipFile | StrPath) -> CompleteDirs:
        """Return a :class:`CompleteDirs`-compatible wrapper around *source*.

        If *source* is already a :class:`CompleteDirs`, it is returned
        unchanged. If it is some other :class:`~ziplet.zipfile.file.ZipFile`
        instance, its ``__class__`` is mutated in place to a
        :class:`CompleteDirs` subclass (this project has no ``__slots__`` on
        :class:`~ziplet.zipfile.file.ZipFile`, so the mutation is safe).
        Otherwise, *source* is treated as an archive filename and opened for
        reading.
        """
        if isinstance(source, CompleteDirs):
            return source

        if not isinstance(source, ZipFile):
            return cls(source)

        # Only allow FastLookup when the supplied ZipFile is read-only.
        target_cls: type[CompleteDirs] = cls
        if "r" not in source.mode:
            target_cls = CompleteDirs

        source.__class__ = target_cls
        return cast(CompleteDirs, source)

    @classmethod
    def inject(cls, zf: ZipFile) -> ZipFile:
        """Write directory entries for any directories implied by *zf*."""
        for name in cls._implied_dirs(zf.namelist()):
            zf.writestr(name, b"")
        return zf


class FastLookup(CompleteDirs):
    """A :class:`CompleteDirs` variant that caches name lookups.

    Only safe to use for read-only archives, where the member list cannot
    change out from under the cache.
    """

    __names: list[str]
    __lookup: set[str]

    def namelist(self) -> list[str]:
        with contextlib.suppress(AttributeError):
            return self.__names
        self.__names = super().namelist()
        return self.__names

    def _name_set(self) -> set[str]:
        with contextlib.suppress(AttributeError):
            return self.__lookup
        self.__lookup = super()._name_set()
        return self.__lookup


class Path:
    """A :mod:`pathlib`-style interface for navigating a ZIP archive.

    Consider a zip file with this structure::

        .
        ├── a.txt
        └── b
            ├── c.txt
            └── d
                └── e.txt

    >>> import io
    >>> data = io.BytesIO()
    >>> zf = ZipFile(data, 'w')
    >>> zf.writestr('a.txt', 'content of a')
    >>> zf.writestr('b/c.txt', 'content of c')
    >>> zf.writestr('b/d/e.txt', 'content of e')
    >>> zf.filename = 'mem/abcde.zip'

    ``Path`` accepts the ``ZipFile`` object itself or a filename.

    >>> path = Path(zf)

    From there, several path operations are available.

    Directory iteration (excluding the zip file itself):

    >>> a, b = path.iterdir()
    >>> a
    Path('mem/abcde.zip', 'a.txt')
    >>> b
    Path('mem/abcde.zip', 'b/')

    ``name`` property:

    >>> b.name
    'b'

    Join with the divide operator:

    >>> c = b / 'c.txt'
    >>> c
    Path('mem/abcde.zip', 'b/c.txt')
    >>> c.name
    'c.txt'

    Read text:

    >>> c.read_text(encoding='utf-8')
    'content of c'

    Existence:

    >>> c.exists()
    True
    >>> (b / 'missing.txt').exists()
    False

    Coercion to string:

    >>> str(c)
    'mem/abcde.zip/b/c.txt'

    At the root, ``name``, ``filename``, and ``parent`` resolve to the
    zipfile.

    >>> str(path)
    'mem/abcde.zip/'
    >>> path.name
    'abcde.zip'
    >>> path.filename == pathlib.Path('mem/abcde.zip')
    True
    >>> str(path.parent)
    'mem'
    """

    __repr_format = "{self.__class__.__name__}({self.root.filename!r}, {self.at!r})"

    root: CompleteDirs
    at: str

    def __init__(self, root: ZipFile | StrPath, at: str = "") -> None:
        """Construct a :class:`Path` from a :class:`ZipFile` or filename.

        Note: when *root* is an existing :class:`~ziplet.zipfile.file.ZipFile`
        instance, its ``__class__`` is mutated to a specialized subclass. If
        the caller needs to retain the original type, pass a filename or a
        separate :class:`~ziplet.zipfile.file.ZipFile` instance instead.

        Args:
            root: An open archive, or a path to one.
            at: The archive-relative POSIX path this :class:`Path` refers to.
                Empty string refers to the archive root.
        """
        self.root = FastLookup.make(root)
        self.at = at

    def __eq__(self, other: object) -> bool:
        """Return whether *other* is a :class:`Path` for the same root and location."""
        if self.__class__ is not other.__class__:
            return NotImplemented
        assert isinstance(other, Path)
        return (self.root, self.at) == (other.root, other.at)

    def __hash__(self) -> int:
        """Return a hash consistent with :meth:`__eq__`."""
        return hash((self.root, self.at))

    def open(
        self,
        mode: str = "r",
        *args: Any,
        pwd: bytes | None = None,
        **kwargs: Any,
    ) -> IO[Any]:
        """Open this entry for reading or writing.

        Follows the semantics of :meth:`pathlib.Path.open`: text mode
        arguments are passed through to :class:`io.TextIOWrapper`.

        Args:
            mode: Any of ``'r'``, ``'rb'``, ``'w'``, ``'wb'`` (text modes
                imply UTF-8-compatible decoding via
                :func:`io.text_encoding` unless *args*/*kwargs* override it).
            pwd: Decryption password for reading an encrypted member. Falls
                back to the archive's default password (set via
                :meth:`~ziplet.zipfile.file.ZipFile.setpassword`) when
                ``None``.

        Raises:
            IsADirectoryError: If this path names a directory.
            FileNotFoundError: If reading and this path does not exist.
            ValueError: If binary mode is combined with text-mode arguments.
        """
        if self.is_dir():
            raise IsADirectoryError(self)
        zip_mode = cast(ReadWriteMode, mode[0])
        if zip_mode == "r" and not self.exists():
            raise FileNotFoundError(self)
        stream = self.root.open(self.at, zip_mode, pwd)
        if "b" in mode:
            if args or kwargs:
                raise ValueError("encoding args invalid for binary operation")
            return stream
        encoding, args, kwargs = _extract_text_encoding(*args, **kwargs)
        return io.TextIOWrapper(stream, encoding, *args, **kwargs)

    def _base(self) -> pathlib.PurePosixPath | pathlib.Path:
        return pathlib.PurePosixPath(self.at) if self.at else self.filename

    @property
    def name(self) -> str:
        """The final path component, or the archive's own filename at the root."""
        return self._base().name

    @property
    def suffix(self) -> str:
        """The final component's last suffix, if any."""
        return self._base().suffix

    @property
    def suffixes(self) -> list[str]:
        """A list of the final component's suffixes."""
        return self._base().suffixes

    @property
    def stem(self) -> str:
        """The final path component, without its suffix."""
        return self._base().stem

    @property
    def filename(self) -> pathlib.Path:
        """The archive filename joined with this path's archive-relative location.

        Raises:
            TypeError: If the underlying archive has no filename (for
                example, an in-memory buffer).
        """
        if self.root.filename is None:
            raise TypeError("root.filename is not set")
        return pathlib.Path(self.root.filename).joinpath(self.at)

    def read_text(self, *args: Any, **kwargs: Any) -> str:
        """Return this member's contents decoded as text."""
        encoding, args, kwargs = _extract_text_encoding(*args, **kwargs)
        with self.open("r", encoding, *args, **kwargs) as strm:
            return cast(str, strm.read())

    def read_bytes(self) -> bytes:
        """Return this member's raw, decompressed contents."""
        with self.open("rb") as strm:
            return cast(bytes, strm.read())

    def _is_child(self, path: Path) -> bool:
        return posixpath.dirname(path.at.rstrip("/")) == self.at.rstrip("/")

    def _next(self, at: str) -> Path:
        return self.__class__(self.root, at)

    def is_dir(self) -> bool:
        """Return whether this path names a directory (including the archive root)."""
        return not self.at or self.at.endswith("/")

    def is_file(self) -> bool:
        """Return whether this path names a file that exists in the archive."""
        return self.exists() and not self.is_dir()

    def exists(self) -> bool:
        """Return whether this path names an entry present in the archive."""
        return self.at in self.root._name_set()

    def iterdir(self) -> Iterator[Path]:
        """Iterate over the direct children of this directory.

        Raises:
            ValueError: If this path does not name a directory.
        """
        if not self.is_dir():
            raise ValueError("Can't listdir a file")
        subs = map(self._next, self.root.namelist())
        return filter(self._is_child, subs)

    def match(self, path_pattern: str) -> bool:
        """Return whether this path matches *path_pattern*."""
        return pathlib.PurePosixPath(self.at).match(path_pattern)

    def is_symlink(self) -> bool:
        """Return whether this path is a symlink."""
        if not self.exists():
            return False
        info = self.root.getinfo(self.at)
        mode = info.external_attr >> 16
        return stat.S_ISLNK(mode)

    def glob(self, pattern: str) -> Iterator[Path]:
        """Yield paths matching the glob *pattern*, relative to this directory.

        Raises:
            ValueError: If *pattern* is empty, or ``**`` appears anywhere
                other than as a full path segment.
        """
        if not pattern:
            raise ValueError(f"Unacceptable pattern: {pattern!r}")

        prefix = re.escape(self.at)
        translator = Translator(seps="/")
        matches = re.compile(prefix + translator.translate(pattern)).fullmatch
        return map(self._next, filter(matches, self.root.namelist()))

    def rglob(self, pattern: str) -> Iterator[Path]:
        """Yield paths matching *pattern* at any depth under this directory."""
        return self.glob(f"**/{pattern}")

    def relative_to(self, other: Path, *extra: str) -> str:
        """Return this path's location relative to *other*."""
        return posixpath.relpath(str(self), str(other.joinpath(*extra)))

    def __str__(self) -> str:
        """Return the archive filename joined with this path."""
        return posixpath.join(str(self.root.filename), self.at)

    def __repr__(self) -> str:
        """Return an unambiguous representation showing the archive and location."""
        return f"{self.__class__.__name__}({self.root.filename!r}, {self.at!r})"

    def joinpath(self, *other: str) -> Path:
        """Return a new :class:`Path` joined with each of *other*."""
        next_at = posixpath.join(self.at, *other)
        return self._next(self.root.resolve_dir(next_at))

    __truediv__ = joinpath

    @property
    def parent(self) -> Path:
        """Return the containing directory."""
        if not self.at:
            return cast(Path, self.filename.parent)
        parent_at = posixpath.dirname(self.at.rstrip("/"))
        if parent_at:
            parent_at += "/"
        return self._next(parent_at)


def _extract_text_encoding(
    encoding: str | None = None, *args: Any, **kwargs: Any
) -> tuple[str | None, tuple[Any, ...], dict[str, Any]]:
    return encoding, args, kwargs
