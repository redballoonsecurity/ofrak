#include <msp430g2553.h>

int i = 0;
int j = 0;
int
main(void)
{
    WDTCTL = WDTPW + WDTHOLD;   //Stop the watch dog timer
    P1DIR |= 0x41;              //Set the direction bit of P1(0x01) as an output

    P1OUT = 0x40;               //Set P1.6 high, P1.0 low

    for(;;) {
        P1OUT ^= 0x41;          //Toggle both P1.1 and P1.6

        for(i = 0; i < 20000;i++){  //Loop for a while to block
            __no_operation();
        }
    }
    return 0;
}
