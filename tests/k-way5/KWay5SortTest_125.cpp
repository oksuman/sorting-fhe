#include "KWay5SortTestTemplate.h"

using Fixture = KWay5SortTest<125>;

TEST_F(Fixture, SortTest) {
    RunKWay5SortTest<125>(this);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
