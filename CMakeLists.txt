﻿#  Copyright (c) Microsoft Corporation. All rights reserved.
#  Licensed under the MIT License.

cmake_minimum_required (VERSION 3.10)

project (azure-sphere-wolfssl-client C)

azsphere_configure_tools(TOOLS_REVISION "20.10")
azsphere_configure_api(TARGET_API_SET "7")

# Create executable
add_executable (${PROJECT_NAME} main.c)
target_link_libraries (${PROJECT_NAME} applibs pthread gcc_s c wolfssl)

azsphere_target_add_image_package(${PROJECT_NAME} RESOURCE_FILES "certs/DigiCertGlobalRootCA.pem")


