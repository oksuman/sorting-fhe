#include "KWay2SortTestTemplate.h"

using TestSizes =
    ::testing::Types<std::integral_constant<size_t, 8>>;

INSTANTIATE_TYPED_TEST_SUITE_P(
    KWay2Sort_8,
    KWay2SortTestFixture,
    TestSizes);

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
