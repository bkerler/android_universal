cmake_minimum_required(VERSION 3.19)
project(sepol VERSION 1.0.1 DESCRIPTION "libsepol special")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
find_package(Qt5Widgets REQUIRED)

set(libsepol_headers
        av_permissions.h
        boolean_internal.h
        context.h
        context_internal.h
        debug.h
        dso.h
        handle.h
        iface_internal.h
        mls.h
        module_internal.h
        node_internal.h
        policydb_internal.h
        port_internal.h
        private.h
        user_internal.h
)

set(LIBSEPOL_SRC_FILES
        assertion.c
        avrule_block.c
        avtab.c
        booleans.c
        boolean_record.c
        conditional.c
        constraint.c
        context.c
        context_record.c
        debug.c
        ebitmap.c
        expand.c
        genbools.c
        genusers.c
        handle.c
        hashtab.c
        hierarchy.c
        iface_record.c
        interfaces.c
        link.c
        mls.c
        module.c
        nodes.c
        node_record.c
        polcaps.c
        policydb.c
        policydb_convert.c
        policydb_public.c
        ports.c
        port_record.c
        roles.c
        services.c
        sidtab.c
        symtab.c
        users.c
        user_record.c
        util.c
        write.c
        )

set(CMAKE_C_FLAGS " \
    -D_GNU_SOURCE \
    -Wall \
    -Werror \
    -Wno-void-pointer-to-enum-cast \
    -Wundef \
    -Wshadow \
    -Wno-error=missing-noreturn \
    -Wmissing-format-attribute \
    ")

include_directories(
        ${libsepol_headers}
        ../include
        sepol
        sepol/policydb
        )

add_library(sepol STATIC ${LIBSEPOL_SRC_FILES})
target_link_libraries(sepol Qt::core)
