static inline elem F(key_schedule_round)(elem k0, elem k1) {
  elem res = xor(k0, sl(k0, 4));
  res = xor(res, sl(res, 8));
  return xor(res, k1);
}

static inline void F(key_schedule)(elem k0, elem k1, elem *res) {
  res[0] = k0;
  res[1] = k1;
  res[2] = k0 = F(key_schedule_round)(k0, F(key_schedule_round1)(k1, 1));
  res[3] = k1 = F(key_schedule_round)(k1, F(key_schedule_round2)(k0));
  res[4] = k0 = F(key_schedule_round)(k0, F(key_schedule_round1)(k1, 2));
  res[5] = k1 = F(key_schedule_round)(k1, F(key_schedule_round2)(k0));
  res[6] = k0 = F(key_schedule_round)(k0, F(key_schedule_round1)(k1, 4));
  res[7] = k1 = F(key_schedule_round)(k1, F(key_schedule_round2)(k0));
  res[8] = k0 = F(key_schedule_round)(k0, F(key_schedule_round1)(k1, 8));
  res[9] = k1 = F(key_schedule_round)(k1, F(key_schedule_round2)(k0));
}

void F(cn_slow_hash)(const void *data, size_t length, char *hash) {
  elem long_state[MEMORY / sizeof(elem)];
  union cn_slow_hash_state state;
  elem keys[10];
  elem text[8];
  elem a, b, c;
#if defined(AES_DEBUG)
  elem shadow_long_state[MEMORY / sizeof(elem)];
  elem shadow_a, shadow_b, zeros;
#endif
  size_t i, j, k;
  hash_process(&state.hs, data, length);
  F(key_schedule)(state.k0, state.k1, keys);
  for (i = 0; i < 8; i++) {
    text[i] = state.init[i];
  }
  for (i = 0; i < MEMORY / sizeof(elem); i += 8) {
    for (j = 0; j < 10; j++) {
      for (k = 0; k < 8; k++) {
        text[k] = F(aesenc)(text[k], keys[j]);
      }
    }
    for (j = 0; j < 8; j++) {
      long_state[i + j] = text[j];
    }
  }

  a = xor(state.k0, state.k2);
  b = xor(state.k1, state.k3);
#if defined(AES_DEBUG)
  memcpy(&shadow_long_state, long_state, MEMORY);
  shadow_a = a;
  shadow_b = b;
#endif
  for (i = 0; i < ITER / 2; i++) {
    /* Dependency chain: address -> read value ------+
     * written value <-+ hard function (AES or MUL) <+
     * next address  <-+
     */
    /* Iteration 1 */
    j = e2i(a, MEMORY / sizeof(elem));
    c = long_state[j];
    c = F(aesenc)(c, a); /* c = xor(aes(c), a) */
    b = xor(b, c);
    SWAP(elem, b, c);
    long_state[j] = c;
    assert(j == e2i(a, MEMORY / sizeof(elem)));
    SWAP(elem, a, b);
    /* Iteration 2 */
    j = e2i(a, MEMORY / sizeof(elem));
    c = long_state[j];
    b = add(b, mul(a, c));
    SWAP(elem, b, c);
    b = xor(b, c);
    long_state[j] = c;
    assert(j == e2i(a, MEMORY / sizeof(elem)));
    SWAP(elem, a, b);
  }
  F(key_schedule)(state.k2, state.k3, keys);
  for (i = 0; i < 8; i++) {
    text[i] = state.init[i];
  }
  for (i = 0; i < MEMORY / sizeof(elem); i += 8) {
    for (j = 0; j < 8; j++) {
      text[j] = xor(text[j], long_state[i + j]);
    }
    for (j = 0; j < 10; j++) {
      for (k = 0; k < 8; k++) {
        text[k] = F(aesenc)(text[k], keys[j]);
      }
    }
  }
  for (i = 0; i < 8; i++) {
    state.init[i] = text[i];
  }
  hash_permutation(&state.hs);
  /*memcpy(hash, &state, 32);*/
  extra_hashes[state.hs.b[0] & 3](&state, 200, hash);
#if defined(AES_DEBUG)
  memset(&zeros, 0, 16);
  for (i = 0; i < ITER / 2; i++) {
    /* Do everything in reverse */
    /* Iteration 2 */
    SWAP(elem, a, b);
    j = e2i(a, MEMORY / sizeof(elem));
    c = long_state[j];
    b = xor(b, c);
    SWAP(elem, b, c);
    b = sub(b, mul(a, c));
    long_state[j] = c;
    assert(j == e2i(a, MEMORY / sizeof(elem)));
    /* Iteration 1 */
    SWAP(elem, a, b);
    j = e2i(a, MEMORY / sizeof(elem));
    c = long_state[j];
    SWAP(elem, b, c);
    b = xor(b, c);
    c = aesdeclast(aesimc(xor(c, a)), zeros); /* c = (aes^-1)(xor(c, a)) */
    long_state[j] = c;
    assert(j == e2i(a, MEMORY / sizeof(elem)));
  }
  assert(memcmp(&a, &shadow_a, 16) == 0 && memcmp(&b, &shadow_b, 16) == 0 &&
    memcmp(long_state, &shadow_long_state, MEMORY) == 0);
#endif
}