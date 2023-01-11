file(GLOB SOURCES "*.cpp")
#file(GLOB SOURCES "*.h")

add_library(lib_reactor ${SOURCES})
#target_sources(reactor_srv PUBLIC ${SOURCES})
#target_sources(reactor_tests PUBLIC ${SOURCES})
