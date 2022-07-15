COMPILE_DEPS = CORE_DEPS + NETTY + JACKSON + CLI

BUNDLES = [
    "//providers/myapp2:onos-providers-myapp2",
]

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.provider.app.cli"],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.myapp2",
    category = "Provider",
    description = "Provide WSA",
    included_bundles = BUNDLES,
    title = "MY WSA Provider",
    url = "http://onosproject.org",
)
