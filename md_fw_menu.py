def print_menu():
    cloop=True
    while cloop:
        print (22 * "-" , "MENU" , 22 * "-")
        print ("\t1. [Infor] {:<24} ".format("Packet information"))
        print ("\t2. [Send] {:<24} ".format("Packet Send"))
        print ("\t0. [Exit] {:<24} ".format("Exit"))
        print (50 * "-")
        try:
            choice =input("Enter your choice [0-2]: ")
            if (int(choice) >=0 and int(choice) <=2):
                cloop = False
        except ValueError:
            print('')
    return choice
if __name__=='__main__':
    print_menu()