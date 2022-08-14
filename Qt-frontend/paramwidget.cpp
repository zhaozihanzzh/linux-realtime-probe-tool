#include "paramwidget.h"
#include "ui_paramwidget.h"
#include<QFile>
#include<QDebug>
#include<QTableWidgetItem>
#include<stdlib.h>

ParamWidget::ParamWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ParamWidget)
{
    ui->setupUi(this);

    ui->tableWidget->setColumnCount(2);
    ui->tableWidget->setHorizontalHeaderLabels(QStringList()<<"param"<<"value");
    ui->tableWidget->setRowCount(3);

    QStringList paramNameList;
    paramNameList<<"enable"<<"irq"<<"latency";

    for(int i=0;i<=2;++i){
        QTableWidgetItem* item=new QTableWidgetItem(paramNameList.at(i));
        item->setFlags(item->flags()&~Qt::ItemIsEditable);
        ui->tableWidget->setItem(i,0,item);
    }

    QStringList valueList;
    QFile file;
    file.setFileName("/proc/realtime_probe_tool/enable");
    file.open(QIODevice::ReadOnly);
    valueList<<QString(file.readLine()).split('\n').at(0);
    file.close();
    file.setFileName("/proc/realtime_probe_tool/irq");
    file.open(QIODevice::ReadOnly);
    valueList<<QString(file.readLine()).split('\n').at(0);
    file.close();
    file.setFileName("/proc/realtime_probe_tool/latency");
    file.open(QIODevice::ReadOnly);
    valueList<<QString(file.readLine()).split('\n').at(0);
    file.close();

    for(int i=0;i<=2;++i){
        ui->tableWidget->setItem(i,1,new QTableWidgetItem(valueList.at(i)));
    }



    connect(ui->tableWidget,&QTableWidget::itemChanged,[=](){qDebug()<<ui->tableWidget->currentItem()->text();});

    connect(ui->pushButton,&QPushButton::clicked,this,&ParamWidget::reviseParam);

}

ParamWidget::~ParamWidget()
{
    delete ui;
}

void ParamWidget::reviseParam()
{
    QString enable=ui->tableWidget->item(0,1)->text();
    QString qscmd="echo '"+enable+"' > /proc/realtime_probe_tool/enable";
    QByteArray qbcmd=qscmd.toLatin1();
    system(qbcmd.data());
}

