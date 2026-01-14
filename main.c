#include "KNXnetIP.h"
#include <stdio.h>

int main(void) {

  /* Initialise socket and server entity */
  initServer();
  /* Start blocking communication state machine */
  KNXnetIPCommStateMachine();

  return EXIT_SUCCESS;
}