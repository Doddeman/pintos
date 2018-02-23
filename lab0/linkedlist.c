#include <stdio.h>
#include <stdlib.h>

typedef struct node {
  int value;
  struct node * next;
} node;

//puts x at the end of the list
void append(node *head, int x){
  node * current = head;
  while (current->next != NULL) {
    current = current->next;
  }
  node * new;
  new = malloc(sizeof(node));
  current->next = new;
  new->value = x;
  new->next = NULL;
}

//puts x at the beginning of the list
void prepend(node *head, int x){
  node * new;
  new = malloc(sizeof(node));
  new->value = x;
  new->next = head->next;
  head->next = new;

}
// prints all elements in the list
void print(node *head){
  node * current = head;
  while(current->next != NULL){
    printf("elem: %d, ",current->next->value);
    current = current->next;
  }
  printf("\n");
}

//input_sorted: find the head element in the list
//larger than x and input x right before that element
void input_sorted(node *head, int x){
  node * current = head;
  while(current->next != NULL){
      if(current->next->value > x){
        break;
      }
      current = current->next;
  }
  node * new;
  new = malloc(sizeof(node));
  new->next = current->next;
  new->value = x;
  current->next = new;
}

//free everything dynamically allocated
void clear(node *head){
    node * current = head->next;
    node * temp;
    head->next = NULL;
    while(current != NULL){
        temp = current->next;
        free(current);
        current = temp;
    }
}

int main( int argc, char ** argv)
{
  struct node head;
  //head = malloc(sizeof(node));
  head.value = -1; /* This value is always ignored */
  head.next = NULL;

  prepend(&head, 3);
  append(&head, 5);
  append(&head, 1);
  append(&head, 20);
  input_sorted(&head, 4);
  clear(&head);
  prepend(&head, 3);
  append(&head, 5);
  append(&head, 1);
  prepend(&head, 20);
  input_sorted(&head, 4);

  print(&head);
  clear(&head);
  //free(head);
}
