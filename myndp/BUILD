COMPILE_DEPS = CORE_DEPS + NETTY + JACKSON + CLI

BUNDLES = [
    "//providers/myndp:onos-providers-myndp",
]

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.provider.myndp.cli"],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.myndpprovider",
    category = "Provider",
    description = "Provide speical NDP on SDN Network",
    included_bundles = BUNDLES,
    title = "MY NDP Provider",
    url = "http://onosproject.org",
)
