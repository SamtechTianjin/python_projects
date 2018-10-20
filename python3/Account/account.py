import tkinter
from tkinter import ttk
from PIL import Image,ImageTk

VERSION = 1.0
ABOUT = """
作者: Sam
版本: {0}
邮箱: samliuming@aliyun.com
非常感谢您的使用 !
""".format(VERSION)
LARGE_FONT= ("Verdana",12,"bold")


class Application(tkinter.Tk):

    def __init__(self):
        super().__init__()
        """ Root Window """
        self.title("Family记账本 V{0}".format(VERSION))
        self.geometry("600x400+100+100")
        self.iconbitmap(default="Panda_Kungfu.ico")
        self.resizable(width=False,height=True)
        """ Menu """
        menu = tkinter.Menu(self)
        """ submenu1 """
        submenu1 = tkinter.Menu(menu,tearoff=0)
        submenu1.add_command(label="新建账户")
        submenu1.add_command(label="选择账户")
        submenu1.add_command(label="删除账户")
        submenu1.add_separator()
        submenu1.add_command(label="退出",command=self.quit)
        menu.add_cascade(label='操作',menu=submenu1)
        """ submenu2 """
        submenu2 = tkinter.Menu(menu,tearoff=0)
        submenu2.add_command(label="按时间查询")
        submenu2.add_command(label="按明细查询")
        menu.add_cascade(label='查询',menu=submenu2)
        """ submenu3 """
        submenu3 = tkinter.Menu(menu,tearoff=0)
        submenu3.add_command(label="联系我们",command=self.help_about)
        menu.add_cascade(label="关于",menu=submenu3)
        self.config(menu=menu)
        """ Parent Frame """
        container = tkinter.Frame(self)
        container.pack(side="top",fill="both",expand=True)
        # container.grid_rowconfigure(0,weight=1)
        # container.grid_columnconfigure(0,weight=1)
        """ Child Frame """
        self.frames = {}
        for F in (HomePage,SearchPage,AboutPage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0,column=0,sticky=tkinter.NSEW)
        self.show_frame(HomePage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

    def help_about(self):
        self.show_frame(AboutPage)


class HomePage(tkinter.Frame):

    def __init__(self,parentFrame,rootwindow):
        super(HomePage, self).__init__(parentFrame)
        # image_file = Image.open("welcome.gif")
        # image = ImageTk.PhotoImage(image_file)
        # image_label = tkinter.Label(self,image=image)
        # image_label.pack()
        label = tkinter.Label(self,text="Home Page",font=LARGE_FONT)
        label.pack()


class SearchPage(tkinter.Frame):

    def __init__(self,parentFrame,rootWindow):
        super(SearchPage, self).__init__(parentFrame)
        label = tkinter.Label(self,text="Search Page",font=LARGE_FONT)
        label.pack()


class AboutPage(tkinter.Frame):

    def __init__(self,parentFrame,rootWindow):
        super(AboutPage, self).__init__(parentFrame)
        label = tkinter.Label(self,text=ABOUT,font=LARGE_FONT)
        label.pack(padx=160,pady=100)



if __name__ == '__main__':
    app = Application()
    app.mainloop()