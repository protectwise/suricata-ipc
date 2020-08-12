find_package(Cbindgen)

SET(CBINDGEN_OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/../src/bindings.h)
add_custom_command(
		OUTPUT ${CBINDGEN_OUTPUT}
		COMMAND ${CBINDGEN_EXECUTABLE} ARGS --lang c --config cbindgen.toml --quiet --output ${CBINDGEN_OUTPUT}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		COMMENT "Running cbindgen to generate ${CBINDGEN_OUTPUT}"
		DEPENDS src/lib.rs
)

add_custom_target(gen-header ALL DEPENDS ${CBINDGEN_OUTPUT})

cargo_build(NAME ipc-plugin-rs)
