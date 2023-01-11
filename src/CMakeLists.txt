file(GLOB SOURCES "*.cpp")
#file(GLOB COMMON "Common.cpp")

#set(OPENSSL_USE_STATIC_LIBS TRUE)
#find_package(OpenSSL REQUIRED)

add_executable(reactor_srv ${SOURCES})

add_subdirectory(reactor)

target_link_libraries(reactor_srv PUBLIC lib_reactor)
#target_sources(reactor_tests PUBLIC ${COMMON})