COMPILE_DEPS = CORE_DEPS + NETTY + JACKSON + CLI

BUNDLES = [
    "//providers/myapp3:onos-providers-myapp3",
]

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.provider.app.cli"],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.myapp3",
    category = "Provider",
    description = "Provide WSA",
    included_bundles = BUNDLES,
    title = "MY WSA Provider",
    url = "http://onosproject.org",
)
