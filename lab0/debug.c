#include <stdio.h>

int main(int argc, char ** argv)
{
  char str[] = "sihtgubed"; //array of char
  char *stri = &str[8];     //stri points to address of last element
  char buf[9];              //Empty array of char length 9
  char *bufi = buf;         //Set bufi to beginning of buf
  char *bufend = &buf[8];   //Set bufend to last element

  //Reverse str
  while (bufi <= bufend){
    *bufi = *stri;
    bufi++;
    stri--;
  }

  //Convert to upper case
  while (bufi >= buf){
    *bufi -= 32; //ASCII
    bufi--;
  }

  //Print result
  while (bufi <= bufend){
    printf("%c", *bufi);
    bufi++;
  }
  printf("\n");
}
