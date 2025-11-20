#include "Hybrid2SortTestTemplate.h"

using TestSizes = ::testing::Types<
    std::integral_constant<size_t, 512>
>;

INSTANTIATE_TYPED_TEST_SUITE_P(
    Hybrid2Sort_512,
    HybridSortTestFixture,
    TestSizes
);

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
