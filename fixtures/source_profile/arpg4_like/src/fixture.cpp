extern "C" int mprofiler_fixture_hot_loop(const int* values, int count) {
    int sum = 0;
    for (int i = 0; i < count; ++i) {
        sum += values[i] * 3;
    }
    return sum;
}

extern "C" int mprofiler_fixture_branchy(const int* values, int count) {
    int score = 0;
    for (int i = 0; i < count; ++i) {
        if ((values[i] & 1) == 0) {
            score += values[i];
        } else {
            score -= values[i];
        }
    }
    return score;
}
