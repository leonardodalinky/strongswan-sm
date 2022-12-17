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

#include "sm3_plugin.h"

#include <library.h>
#include "sm3_hasher.h"

typedef struct private_sm3_plugin_t private_sm3_plugin_t;

/**
 * private data of sm3_plugin
 */
struct private_sm3_plugin_t {

	/**
	 * public functions
	 */
	sm3_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_sm3_plugin_t *this)
{
	return "sm3";
}

METHOD(plugin_t, get_features, int,
	private_sm3_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(HASHER, sm3_hasher_create),
			PLUGIN_PROVIDE(HASHER, HASH_SM3),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_sm3_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *sm3_plugin_create()
{
	private_sm3_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}

