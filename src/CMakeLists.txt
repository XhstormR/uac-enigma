set(APP_NAME main)

aux_source_directory(. SOURCE)

if(rdi)
    aux_source_directory(./rdi SOURCE)
else()
    list(APPEND SOURCE ./resources/resource.rc)
endif()

add_library(${APP_NAME} SHARED ${SOURCE})

target_link_libraries(${APP_NAME}
    PRIVATE ole32
)

if(rdi)
    target_compile_definitions(${APP_NAME}
        PRIVATE -Drdi
        PRIVATE -DWIN_X64
        PRIVATE -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
    )
endif()

install(TARGETS ${APP_NAME} RUNTIME DESTINATION bin)
install(PROGRAMS ${PROJECT_SOURCE_DIR}/assets/start.vbs TYPE BIN)
