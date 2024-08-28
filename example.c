#include <stdio.h>

int main(){
    int value = 41;
    int choice;
    while (1){
        printf("Write 1 to add one to value, write 2 to subtract 2 from value. Current value is %d\n",value);
        scanf("%d",&choice);
        if (choice == 1){
            value += 1;
        }
        else if (choice == 2) {
            value -= 2;
        }
    }
}
