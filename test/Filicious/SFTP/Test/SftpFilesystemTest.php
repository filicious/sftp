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

namespace Filicious\Test\Local;

use Filicious\Test\AbstractSingleFilesystemTest;

/**
 * Generated by PHPUnit_SkeletonGenerator on 2012-10-17 at 10:24:36.
 */
class SftpFilesystemTest
	extends AbstractSingleFilesystemTest
{
	/**
	 * @return LocalFilesystemTestEnvironment
	 */
	protected function setUpEnvironment()
	{
		return new SftpFilesystemTestEnvironment();
	}
}