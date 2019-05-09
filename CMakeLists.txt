cmake_minimum_required(VERSION 3.14.0)
project(chacha20 VERSION 0.2.0)
project(chacha20 CXX)

include(CTest)
enable_testing()

add_executable(chacha20 main.cpp chacha20.cpp)
target_compile_features(chacha20 PUBLIC cxx_std_17)

set( BOOST_VERSION 1.70.0 )
#find_package(Boost ${BOOST_VERSION} EXACT REQUIRED COMPONENTS filesystem)
set( Boost_FOUND False )

if(Boost_FOUND)

    set_target_properties( Boost::boost
                           Boost::filesystem
                           PROPERTIES IMPORTED_GLOBAL TRUE )

    set( Boost_USE_STATIC_LIBS      TRUE )
    set( Boost_USE_MULTITHREADED    TRUE )
    set( Boost_USE_STATIC_RUNTIME   FALSE )
    set( Boost_ADDITIONAL_VERSIONS  "${BOOST_VERSION}" )
    set( Boost_COMPILER             "-vc142" )

    target_link_libraries(chacha20 Boost::filesystem)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
