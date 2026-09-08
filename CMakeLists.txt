set(BIP138_SRCS
    src/bip138_varint.c
    src/bip138_secret.c
    src/bip138_paths.c
    src/bip138_payload.c
    src/bip138_container.c
    src/bip138_base64.c)

if(ESP_PLATFORM)
    idf_component_register(
        SRCS ${BIP138_SRCS}
        INCLUDE_DIRS "include"
        PRIV_INCLUDE_DIRS "src")
    target_compile_options(${COMPONENT_LIB} PRIVATE -Werror=unused-result)
else()
    cmake_minimum_required(VERSION 3.16)
    project(bip138 C)
    add_library(bip138 STATIC ${BIP138_SRCS})
    target_include_directories(bip138 PUBLIC include PRIVATE src)
    set_target_properties(bip138 PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_options(bip138 PRIVATE -Wall -Wextra -Werror=unused-result)
endif()
