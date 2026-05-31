#
# Copyright (c) 2018 O.S.Systems
#
# SPDX -License-Identifier: Apache-2.0
#

set_ifndef(CSTD c99)

zephyr_library()

include_directories_ifdef(CONFIG_HOTPATCH include)
zephyr_library_sources_ifdef(CONFIG_HOTPATCH src/hp_manager.c)
zephyr_library_sources_ifdef(CONFIG_HOTPATCH src/hp_guard.c)
zephyr_library_sources_ifdef(CONFIG_HOTPATCH src/hp_applicator.c)
zephyr_library_sources_ifdef(CONFIG_HOTPATCH src/hp_slot.c)
zephyr_library_sources_ifdef(CONFIG_HOTPATCH src/hp_code.c)
zephyr_library_sources_ifdef(CONFIG_HOTPATCH src/hp_measure.c)

#zephyr_library_sources_ifdef(CONFIG_HOTPATCH src/util/hp_linked_list.c)


zephyr_linker_sources(RAM_SECTIONS hp_layout_zephyr.ld)
