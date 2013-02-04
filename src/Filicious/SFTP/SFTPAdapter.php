<?php

/**
 * High level object oriented filesystem abstraction.
 *
 * @package filicious-core
 * @author  Tristan Lins <tristan.lins@bit3.de>
 * @author  Christian Schiffler <c.schiffler@cyberspectrum.de>
 * @author  Oliver Hoff <oliver@hofff.com>
 * @link    http://filicious.org
 * @license http://www.gnu.org/licenses/lgpl-3.0.html LGPL
 */

namespace Filicious\SFTP;

use Filicious\File;
use Filicious\FilesystemConfig;
use Filicious\Internals\Adapter;
use Filicious\Internals\AbstractAdapter;
use Filicious\Internals\Pathname;
use Filicious\Exception\AdapterException;
use Filicious\Exception\FilesystemException;
use Filicious\Exception\FilesystemOperationException;
use Filicious\Exception\DirectoryOverwriteDirectoryException;
use Filicious\Exception\DirectoryOverwriteFileException;
use Filicious\Exception\FileOverwriteDirectoryException;
use Filicious\Exception\FileOverwriteFileException;
use Filicious\Internals\BoundFilesystemConfig;
use Filicious\Internals\Util;
Use Filicious\Stream\BuildInStream;

/**
 * Local filesystem adapter.
 *
 * @package filicious-core
 * @author  Tristan Lins <tristan.lins@bit3.de>
 */
class SFTPAdapter
	extends AbstractAdapter
{
	const CONFIG_KEY = 'KEY';

	const CONFIG_KEY_FILE = 'KEY_FILE';

	/**
	 * @var string
	 */
	protected $connectionURL;

	/**
	 * @var \Net_SFTP
	 */
	protected $connection;

	/**
	 * @var string
	 */
	protected $basepath;

	/**
	 * @param string|FilesystemConfig $host
	 * @param int $port
	 * @param string $username
	 * @param string $password
	 * @param string $keyfile
	 * @param string $basepath
	 */
	public function __construct($host = null, $port = null, $username = null, $password = null, $key = null, $basepath = null)
	{
		$this->config = new BoundFilesystemConfig($this);
		$this->config
			->open()
			->set(FilesystemConfig::BASEPATH, null);

		if ($basepath instanceof FilesystemConfig) {
			$this->config->merge($basepath);
		}
		else if(is_string($host)) {
			$this->config->set(FilesystemConfig::HOST, $host);
			if ($port) {
				$this->config->set(FilesystemConfig::PORT, $port);
			}
			if ($username) {
				$this->config->set(FilesystemConfig::USERNAME, $username);
			}
			if ($password) {
				$this->config->set(FilesystemConfig::PASSWORD, $password);
			}
			if ($key) {
				if (is_file($key)) {
					$this->config->set(self::CONFIG_KEY_FILE, $key);
				}
				else {
					$this->config->set(self::CONFIG_KEY, $key);
				}
			}
			if ($basepath) {
				$this->config->set(FilesystemConfig::BASEPATH, $basepath);
			}
		}

		$this->config
			->set(FilesystemConfig::IMPLEMENTATION, __CLASS__)
			->commit();
	}

	/**
	 * @return \Net_SFTP
	 * @throws \Exception
	 */
	protected function getConnection()
	{
		if (!$this->connection) {
			$host = $this->config->get(FilesystemConfig::HOST);
			$port = $this->config->get(FilesystemConfig::PORT, 22);
			$username = $this->config->get(FilesystemConfig::USERNAME);
			$password = $this->config->get(FilesystemConfig::PASSWORD, '');
			$key = $this->config->get(self::CONFIG_KEY);
			$keyFile = $this->config->get(self::CONFIG_KEY_FILE);
			$basepath = Util::normalizePath('/' . $this->config->get(FilesystemConfig::BASEPATH, ''));

			if ($keyFile) {
				$key = file_get_contents($keyFile);
			}

			if ($key) {
				$key = new \Crypt_RSA();

				if ($password) {
					$key->setPassword($password);
				}

				$key->loadKey($key);
				$password = $key;
			}

			$connection = new \Net_SFTP($host, $port);

			if (!$connection->login($username, $password)) {
				throw new \Exception(
					sprintf(
						'Could not login to %s',
						$host
					)
				);
			}

			if ($basepath != '/') {
				$connection->chdir($basepath);
			}

			$this->connection = $connection;
			$this->basepath = $connection->pwd() . '/';
		}

		return $this->connection;
	}

	/**
	 * @return string
	 */
	protected function getBasepath()
	{
		return $this->basepath;
	}

	/**
	 * Tests whether the file denoted by the given pathname exists and is a
	 * file.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 *
	 * @return bool True, if the file exists and is a file; otherwise false
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function isFile(Pathname $pathname)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());
		return $stat && $stat['type'] == NET_SFTP_TYPE_REGULAR;
	}

	/**
	 * Tests whether the file denoted by the given pathname exists and is a
	 * directory.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return bool True, if the file exists and is a directory; otherwise false
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function isDirectory(Pathname $pathname)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());
		return $stat && $stat['type'] == NET_SFTP_TYPE_DIRECTORY;
	}

	/**
	 * Tests whether the file denoted by the given pathname exists and is a
	 * link.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return bool True, if the file exists and is a link; otherwise false
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function isLink(Pathname $pathname)
	{
		$stat = $this->getConnection()->lstat($this->getBasepath() . $pathname->local());
		return $stat && $stat['type'] == NET_SFTP_TYPE_SYMLINK;
	}

	/**
	 * Returns the time of the file named by the given pathname was accessed
	 * last time.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return \DateTime
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getAccessTime(Pathname $pathname)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		if (!$stat) {
			throw new FileNotFoundException($pathname);
		}

		return $stat['atime'];
	}

	/**
	 * Sets the access time of the file named by the given pathname.
	 *
	 * @param string    $pathname The full abstracted pathname
	 * @param string    $local    The adapter local path
	 * @param \DateTime $atime
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function setAccessTime(Pathname $pathname, \DateTime $atime)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Returns the time of the file named by the given pathname at which it was
	 * created.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return \DateTime The creation time of the file
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getCreationTime(Pathname $pathname)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		if (!$stat) {
			throw new FileNotFoundException($pathname);
		}

		return $stat['mtime'];
	}

	/**
	 * Returns the time of the file named by the given pathname was modified
	 * last time.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return \DateTime The modify time of the file
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getModifyTime(Pathname $pathname)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		if (!$stat) {
			throw new FileNotFoundException($pathname);
		}

		return $stat['mtime'];
	}

	/**
	 * Sets the modify time of the file named by the given pathname.
	 *
	 * @param string    $pathname The full abstracted pathname
	 * @param string    $local    The adapter local path
	 * @param \DateTime $mtime    The new modify time to set
	 * @return void
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function setModifyTime(Pathname $pathname, \DateTime $mtime)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Sets access and modify time of file, optionally creating the file, if it
	 * does not exists yet.
	 *
	 * @param string    $pathname The full abstracted pathname
	 * @param string    $local    The adapter local path
	 * @param \DateTime $time     The new modify time to set
	 * @param \DateTime $atime    The new access time to set; If null then $time
	 *                            will be used
	 * @param bool      $create   Whether to create the file, if it does not already
	 *                            exists
	 * @return void
	 * @throws FileStateException If the file does not exists and $create is set
	 *         to false
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function touch(Pathname $pathname, \DateTime $time, \DateTime $atime, $create)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Get the size of the file named by the given pathname.
	 *
	 * @param string $pathname  The full abstracted pathname
	 * @param string $local     The adapter local path
	 * @param bool   $recursive Whether or not to calculate the size of
	 *                          directories.
	 * @return numeric The size of the file
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getSize(Pathname $pathname, $recursive)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		if (!$stat) {
			throw new FileNotFoundException($pathname);
		}

		if ($stat['type'] == NET_SFTP_TYPE_DIRECTORY) {
			if ($recursive) {
				$size = 0;

				$iterator = $this->getIterator($pathname, array());

				foreach ($iterator as $pathname) {
					$size += $this->fs
						->getFile($pathname)
						->getSize(true);
				}

				return $size;
			}

			return 0;
		}
		else {
			return $stat['size'];
		}
	}

	/**
	 * Get the owner of the file named by the given pathname.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return string|int
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getOwner(Pathname $pathname)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		if (!$stat) {
			throw new FileNotFoundException($pathname);
		}

		return $stat['uid'];
	}

	/**
	 * Set the owner of the file named by the given pathname.
	 *
	 * @param string     $pathname The full abstracted pathname
	 * @param string     $local    The adapter local path
	 * @param string|int $user
	 * @return void
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function setOwner(Pathname $pathname, $user)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Get the group of the file named by the given pathname.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return string|int
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getGroup(Pathname $pathname)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		if (!$stat) {
			throw new FileNotFoundException($pathname);
		}

		return $stat['gid'];
	}

	/**
	 * Change the group of the file named by the given pathname.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @param mixed  $group
	 * @return void
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function setGroup(Pathname $pathname, $group)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Get the mode of the file named by the given pathname.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return int TODO mode representation type?
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getMode(Pathname $pathname)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		if (!$stat) {
			throw new FileNotFoundException($pathname);
		}

		return $stat['permissions'];
	}

	/**
	 * Set the mode of the file named by the given pathname.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @param int    $mode     TODO mode representation type?
	 * @return void
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function setMode(Pathname $pathname, $mode)
	{
		$this->getConnection()->chmod($mode, $this->getBasepath() . $pathname->local());
	}

	/**
	 * Tests whether the file named by the given pathname is readable.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return bool True, if the file exists and is readable; otherwise false
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function isReadable(Pathname $pathname)
	{
		return (bool) ($this->getMode($pathname) & 292);
	}

	/**
	 * Tests whether the file named by the given pathname is writable.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return bool True, if the file exists and is writable; otherwise false
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function isWritable(Pathname $pathname)
	{
		return (bool) ($this->getMode($pathname) & 146);
	}

	/**
	 * Tests whether the file named by the given pathname is executeable.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return bool True, if the file exists and is executable; otherwise false
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function isExecutable(Pathname $pathname)
	{
		return (bool) ($this->getMode($pathname) & 73);
	}

	/**
	 * Checks whether a file or directory exists.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return bool
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function exists(Pathname $pathname)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		return (bool) $stat;
	}

	/**
	 * Delete a file or directory.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @param bool   $recursive
	 * @param bool   $force
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function delete(Pathname $pathname, $recursive, $force)
	{
		if ($this->isDirectory($pathname)) {
			if ($recursive || $this->count($pathname, array()) == 0) {
				$this->getConnection()->delete($this->getBasepath() . $pathname->local(), true);
			}
		}
		else {
			$this->getConnection()->delete($this->getBasepath() . $pathname->local(), $recursive);
		}
	}

	public function nativeMove(
		Pathname $srcPathname,
		Pathname $dstPathname
	) {
		if ($srcPathname->localAdapter() == $dstPathname->localAdapter()) {
			return $this->getConnection()->rename(
				$srcPathname->localAdapter()->getBasepath() . $srcPathname->local(),
				$dstPathname->localAdapter()->getBasepath() . $dstPathname->local()
			);
		}
		return false;
	}

	/**
	 * Makes directory
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @param bool   $parents
	 * @return void
	 * @throws FileStateException If the file does already exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function createDirectory(Pathname $pathname, $parents)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		if ($stat) {
			if (!$stat['type'] == NET_SFTP_TYPE_DIRECTORY) {
				throw new AdapterException(
					sprintf(
						'Pathname %s already exists and is not a directory',
						$pathname->full()
					)
				);
			}
		}

		if (!$this->getConnection()->mkdir($this->getBasepath() . $pathname->local())) {
			throw new AdapterException(
				sprintf(
					'Could not create directory %s',
					$pathname->full()
				)
			);
		}
	}

	/**
	 * Create new empty file.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @param bool   $parents
	 * @return void
	 * @throws FileStateException If the file does already exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function createFile(Pathname $pathname, $parents)
	{
		$stat = $this->getConnection()->stat($this->getBasepath() . $pathname->local());

		if ($stat) {
			if (!$stat['type'] == NET_SFTP_TYPE_REGULAR) {
				throw new AdapterException(
					sprintf(
						'Pathname %s already exists and is not a file',
						$pathname->full()
					)
				);
			}
		}

		// TODO handle $parents
		if (!$this->getConnection()->put($this->getBasepath() . $pathname->local(), '')) {
			throw new AdapterException(
				sprintf(
					'Could not create file %s',
					$pathname->full()
				)
			);
		}
	}

	/**
	 * Get contents of the file. Returns <em>null</em> if file does not exists
	 * and <em>false</em> on error (e.a. if file is a directory).
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return string
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getContents(Pathname $pathname)
	{
		return $this->getConnection()->get($this->getBasepath() . $pathname->local());
	}

	/**
	 * Write contents to a file. Returns <em>false</em> on error (e.a. if file is a directory).
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @param string $content
	 * @param bool   $create
	 * @return void
	 * @throws FileStateException If the file does not exists and $create is set
	 *         to false
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function setContents(Pathname $pathname, $content, $create)
	{
		// TODO handle $create
		$this->getConnection()->put($this->getBasepath() . $pathname->local(), $content);
	}

	/**
	 * Write contents to a file. Returns <em>false</em> on error (e.a. if file is a directory).
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @param string $content
	 * @param bool   $create
	 * @return void
	 * @throws FileStateException If the file does not exists and $create is set
	 *         to false
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function appendContents(Pathname $pathname, $content, $create)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Truncate a file to a given length. Returns the new length or
	 * <em>false</em> on error (e.a. if file is a directory).
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @param int    $size
	 * @return void
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function truncate(Pathname $pathname, $size)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Gets an stream for the file. May return <em>null</em> if streaming is not supported.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @return Stream
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getStream(Pathname $pathname)
	{
		$this->checkFile($pathname);

		$temp = tempnam(sys_get_temp_dir(), 'sftp2_stream_');

		$this->getConnection()->get($this->getBasepath() . $pathname->local(), $temp);

		register_shutdown_function(
			function() use ($temp) {
				unlink($temp);
			}
		);

		return new BuildInStream($temp, $pathname);
	}

	/**
	 * Get the real url, e.g. file:/real/path/to/file to the pathname.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return string
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getStreamURL(Pathname $pathname)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Get mime content type.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return string
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getMIMEName(Pathname $pathname)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Get mime content type.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return string
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getMIMEType(Pathname $pathname)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Get mime content type.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return string
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getMIMEEncoding(Pathname $pathname)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Returns all filenames of all (direct) children.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return array<Filicious\File>
	 * @throws FileStateException If the file does not exists or is not a
	 *         directory
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function ls(Pathname $pathname)
	{
		$files = $this->getConnection()->nlist($this->getBasepath() . $pathname->local());

		natcasesort($files);

		return array_values(
			array_filter(
				$files,
				function ($file) {
					return $file !== '.' && $file !== '..';
				}
			)
		);
	}

	/**
	 * Returns the available space of the disk or partition or system
	 * the directory denoted by pathname resides on.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return float The amount of free space available in bytes
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getFreeSpace(Pathname $pathname)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Returns the total size of the disk or partition or system the directory
	 * denoted by pathname resides on.
	 *
	 * @param string $pathname The full abstracted pathname
	 * @param string $local    The adapter local path
	 * @return float The total size in bytes
	 * @throws FileStateException If the file does not exists
	 * @throws AdapterException If the access to the underlying filesystem fails
	 *         due to technical reasons like connection problems or timeouts
	 */
	public function getTotalSpace(Pathname $pathname)
	{
		throw new AdapterException('Unsupported operation');
	}

	/**
	 * Notify about config changes.
	 */
	public function notifyConfigChange()
	{
		$host = $this->config->get(FilesystemConfig::HOST);
		$port = $this->config->get(FilesystemConfig::PORT);
		$username = $this->config->get(FilesystemConfig::USERNAME);
		$password = $this->config->get(FilesystemConfig::PASSWORD);
		$key = $this->config->get(self::CONFIG_KEY);
		$keyFile = $this->config->get(self::CONFIG_KEY_FILE);
		$basepath = $this->config->get('/' . FilesystemConfig::BASEPATH);

		if ($basepath) {
			$basepath = Util::normalizePath($basepath);
		}

		$connectUrl = $username;
		if ($keyFile) {
			$connectUrl .= ':' . crypt($keyFile . $password);
		}
		else if ($key) {
			$connectUrl .= ':' . crypt($key . $password);
		}
		else if ($password) {
			$connectUrl .= ':' . crypt($password);
		}
		$connectUrl .= '@' . $host;
		if ($port) {
			$connectUrl .= ':' . $port;
		}
		$connectUrl .= $basepath;

		if ($this->connectionURL != $connectUrl) {
			if ($this->connection) {
				$this->connection->disconnect();
				$this->connection = null;
			}
			$this->connectionURL = $connectUrl;
		}
	}
}
