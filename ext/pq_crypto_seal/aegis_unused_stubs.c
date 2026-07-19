/*
 * pq_crypto-seal exposes only AEGIS-256. libaegis common.c initializes all
 * optional families, so source-only builds provide no-op selectors for the
 * families deliberately not linked into this extension.
 */
int aegis128l_pick_best_implementation(void) {
    return 0;
}
int aegis128x2_pick_best_implementation(void) {
    return 0;
}
int aegis128x4_pick_best_implementation(void) {
    return 0;
}
int aegis256x2_pick_best_implementation(void) {
    return 0;
}
int aegis256x4_pick_best_implementation(void) {
    return 0;
}
