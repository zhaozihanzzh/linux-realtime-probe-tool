#include "mainwindow.h"
#include "ui_mainwindow.h"
#include"processinfowidget.h"
#include"paramwidget.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QWidget* widget1=new ParamWidget(this);
    ui->tabWidget->addTab(widget1,"模块参数");

    QWidget* widget2=new ProcessInfoWidget(this);
    ui->tabWidget->addTab(widget2,"抓取到的进程信息");
}

MainWindow::~MainWindow()
{
    delete ui;
}



