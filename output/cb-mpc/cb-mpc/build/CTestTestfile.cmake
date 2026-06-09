# CMake generated Testfile for 
# Source directory: /home/kali/CascadeProjects/VULSCAN-X/targets/cb-mpc
# Build directory: /home/kali/CascadeProjects/VULSCAN-X/output/cb-mpc/cb-mpc/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(PublicHeadersSmoke "/usr/bin/cmake" "--build" "/home/kali/CascadeProjects/VULSCAN-X/output/cb-mpc/cb-mpc/build" "--target" "public-only-check")
set_tests_properties(PublicHeadersSmoke PROPERTIES  LABELS "unit" RUN_SERIAL "TRUE" _BACKTRACE_TRIPLES "/home/kali/CascadeProjects/VULSCAN-X/targets/cb-mpc/CMakeLists.txt;146;add_test;/home/kali/CascadeProjects/VULSCAN-X/targets/cb-mpc/CMakeLists.txt;0;")
subdirs("src/cbmpc/core")
subdirs("src/cbmpc/crypto")
subdirs("src/cbmpc/zk")
subdirs("src/cbmpc/protocol")
subdirs("src/cbmpc/api")
subdirs("src/cbmpc/c_api")
subdirs("tests")
