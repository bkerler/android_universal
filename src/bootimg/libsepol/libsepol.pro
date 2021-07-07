#-------------------------------------------------
#
# Project created by QtCreator 2018-09-01T12:52:53
#
#-------------------------------------------------

QT       -= core

TARGET = mysepol
TEMPLATE = lib
CONFIG += staticlib

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    "assertion.c" \
    "avrule_block.c" \
    "avtab.c" \
    "booleans.c" \
    "boolean_record.c" \
    "conditional.c" \
    "constraint.c" \
    "context.c" \
    "context_record.c" \
    "debug.c" \
    "ebitmap.c" \
    "expand.c" \
    "genbools.c" \
    "genusers.c" \
    "handle.c" \
    "hashtab.c" \
    "hierarchy.c" \
    "iface_record.c" \
    "interfaces.c" \
    "link.c" \
    "mls.c" \
    "module.c" \
    "nodes.c" \
    "node_record.c" \
    "polcaps.c" \
    "policydb.c" \
    "policydb_convert.c" \
    "policydb_public.c" \
    "ports.c" \
    "port_record.c" \
    "roles.c" \
    "services.c" \
    "sidtab.c" \
    "symtab.c" \
    "users.c" \
    "user_record.c" \
    "util.c" \
    "write.c"


HEADERS += \
    "av_permissions.h" \
    "boolean_internal.h" \
    "context.h" \
    "context_internal.h" \
    "debug.h" \
    "dso.h" \
    "handle.h" \
    "iface_internal.h" \
    "mls.h" \
    "module_internal.h" \
    "node_internal.h" \
    "policydb_internal.h" \
    "port_internal.h" \
    "private.h" \
    "user_internal.h"

win32 {
 INCLUDEPATH += $$PWD/../include
 DEPENDPATH += $$PWD/../include
}

unix {
    target.path = /usr/lib
    INSTALLS += target
}

win32:CONFIG(release, debug|release): DESTDIR = $$PWD/Win/release
else:win32:CONFIG(debug, debug|release): DESTDIR = $$PWD/Win/debug
else:unix:!macx:CONFIG(debug, debug|release): DESTDIR = $$PWD/Linux/debug
else:unix:!macx:CONFIG(release, debug|release): DESTDIR = $$PWD/Linux/release
