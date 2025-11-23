cmake_minimum_required(VERSION 4.1)

project(RcloneMountExt LANGUAGES C)

include(GNUInstallDirs)

# Where are binaries installed
set(INSTALL_BIN_DIR "${CMAKE_INSTALL_FULL_BINDIR}")

# Where to run cargo
set(CARGO_TARGET_DIR ${CMAKE_BINARY_DIR}/cargo_target)

# Tell CMake to build Rust binary
add_custom_target(build_rust ALL
    COMMAND cargo build --release --target-dir ${CARGO_TARGET_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# Rust binary full path
set(RCLONE_MOUNT_EXT_BIN ${CARGO_TARGET_DIR}/release/rclone-mount-ext)

# Configure files
configure_file(${CMAKE_SOURCE_DIR}/pkg/lib/systemd/system/rclone-mount-ext@.service.in
    ${CMAKE_BINARY_DIR}/lib/systemd/system/rclone-mount-ext@.service
    @ONLY
)
configure_file(${CMAKE_SOURCE_DIR}/pkg/bin/rclone-mount-ext-helper.in
    ${CMAKE_BINARY_DIR}/bin/rclone-mount-ext-helper
    @ONLY
)

# Install executables
install(PROGRAMS
        ${RCLONE_MOUNT_EXT_BIN}
        ${CMAKE_BINARY_DIR}/bin/rclone-mount-ext-helper
    TYPE BIN
)

# Install lib files
install(FILES
        ${CMAKE_BINARY_DIR}/lib/systemd/system/rclone-mount-ext@.service
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system
)
