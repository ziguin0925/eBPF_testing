# $Id$

TOP=	.

.include "${TOP}/mk/elftoolchain.components.mk"
.include "${TOP}/mk/elftoolchain.os.mk"

# Build configuration information first.
SUBDIR += common

# Build the base libraries next.
SUBDIR += libelf
.if defined(WITH_PE) && ${WITH_PE} == "yes"
SUBDIR += libpe
.endif

# The instruction set analyser.
.if defined(WITH_ISA) && ${WITH_ISA} == "yes"
SUBDIR += isa  # ('isa' does not build on all platforms yet).
.endif

# Build tools after the libraries.

# Build the test suites.
.if exists(${.CURDIR}/test) && defined(WITH_TESTS) && ${WITH_TESTS} == "yes"
SUBDIR += test
.endif

# Build additional build tooling.
.if defined(WITH_BUILD_TOOLS) && ${WITH_BUILD_TOOLS} == "yes"
SUBDIR += tools
.endif

# Build documentation at the end.
.if exists(${.CURDIR}/documentation) && \
    defined(WITH_ADDITIONAL_DOCUMENTATION) && \
    ${WITH_ADDITIONAL_DOCUMENTATION} == "yes"
SUBDIR += documentation
.endif

.include "${TOP}/mk/elftoolchain.subdir.mk"

#
# Special top-level targets.
#

# Run the test suites.
.if exists(${.CURDIR}/test) && defined(WITH_TESTS) && ${WITH_TESTS} == "yes"
run-tests:	all .PHONY
	(cd ${.CURDIR}/test; ${MAKE} test)
.endif
