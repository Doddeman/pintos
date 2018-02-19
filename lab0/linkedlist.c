#include <stdio.h>
#include <stdlib.h>

typedef struct list_item {
  int value;
  struct list_item * next;
} node;

//puts x at the end of the list
void append(node *first, int x){
  node * current = first;
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
void prepend(node *first, int x){
  node * new;
  new = malloc(sizeof(node));
  new->value = x;
  new->next = first->next;
  first->next = new;

}
// prints all elements in the list
void print(node *first){
  node * current = first;
  while(current->next != NULL){
    printf("elem: %d, ",current->next->value);
    current = current->next;
  }
  printf("\n");
}

//input_sorted: find the first element in the list
//larger than x and input x right before that element
void input_sorted(node *first, int x){
  node * current = first;
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
void clear(node *first){
  node * current = first;
  while(current->next != NULL){
    free(current);
    current = current->next;
  }
  free(current);
  first->next = NULL;
}

int main( int argc, char ** argv)
{
  node * root;
  root = malloc(sizeof(node));
  //struct node root; //no dynamic memory allocation. no memory must be freed
  root->value = -1; /* This value is always ignored */
  root->next = NULL;

  prepend(root, 3);
  append(root, 5);
  append(root, 1);
  append(root, 20);
  input_sorted(root, 4);
  clear(root);
  prepend(root, 3);
  append(root, 5);
  append(root, 1);
  append(root, 20);
  input_sorted(root, 4);

  print(root);

}
