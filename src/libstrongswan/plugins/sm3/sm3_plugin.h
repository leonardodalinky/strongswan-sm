/*
 * Copyright (C) 2008 Martin Willi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * Modified by Leonardodalinky 2022
 * 
 * 本模块用于提供 SM3 哈希算法的实现
 */

/**
 * @defgroup sm3_p sm3
 * @ingroup plugins
 *
 * @defgroup sm3_plugin sm3_plugin
 * @{ @ingroup sm3_p
 */

#ifndef SM3_PLUGIN_H_
#define SM3_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct sm3_plugin_t sm3_plugin_t;

/**
 * Plugin implementing the sm3 hash algorithm in software.
 */
struct sm3_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** SM3_PLUGIN_H_ @}*/
