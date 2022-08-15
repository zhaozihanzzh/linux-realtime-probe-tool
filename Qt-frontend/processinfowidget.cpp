#include "processinfowidget.h"
#include "ui_processinfowidget.h"
#include<QFile>
#include<QDebug>
#include<QMessageBox>
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<algorithm>

ProcessInfoWidget::ProcessInfoWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ProcessInfoWidget)
{
    ui->setupUi(this);

    this->setInfo();
    // 上一页
    connect(ui->pushButton_1,&QPushButton::clicked,[=](){
        if(currPage > 1) {
            --currPage;
            ui->lineEdit->setText(QString::number(currPage));
            ui->textBrowser->setText(infoList.at(currPage-1));
        }
    });
    // 下一页
    connect(ui->pushButton_2,&QPushButton::clicked,[=](){
        if(currPage < maxPage) {
            ++currPage;
            ui->lineEdit->setText(QString::number(currPage));
            ui->textBrowser->setText(infoList.at(currPage-1));
        }
    });
    // 跳转
    connect(ui->pushButton_3,&QPushButton::clicked,[=](){
        int targetPage=ui->lineEdit->text().toInt();
        if(targetPage <= maxPage && targetPage >= 1) {
            currPage=targetPage;
            ui->textBrowser->setText(infoList.at(currPage-1));
        } else {
            QMessageBox::critical(this,"错误","输入的记录序号超出范围，请重新输入");
        }
    });

    // comm筛选
    connect(ui->pushButton_5,&QPushButton::clicked,[=](){
        QString comm=ui->lineEdit_2->text();
        if(!comm.isEmpty()) {
            infoList.clear();
            for(int page=1;page<=initialInfoList.size();++page) {
                QString firstLine=initialInfoList.at(page-1).split('\n').at(0);
                QString pattern("IRQ disabled \\d*ns on cpu \\d* by pid \\d*, comm (.*)");
                QRegExp reg(pattern);
                firstLine.indexOf(reg);
                if(reg.cap(1)==comm) {
                    infoList.append(initialInfoList.at(page-1));
                }
            }
            ui->label_5->setText(QString("共 ")+QString::number(infoList.size())+QString(" 条记录"));
            if(!infoList.isEmpty()) {
                this->currPage=1;
                this->maxPage=infoList.size();
                ui->lineEdit->setText(QString::number(currPage));
                ui->textBrowser->setText(infoList.at(0));
            } else {
                this->currPage=1;
                this->maxPage=1;
                ui->lineEdit->setText(QString::number(currPage));
                ui->textBrowser->setText("没有符合条件的记录！");
            }
        }
    });

    // 取消筛选
    connect(ui->pushButton_6,&QPushButton::clicked,this,&ProcessInfoWidget::cancelFilter);

    // pid筛选
    connect(ui->pushButton_7,&QPushButton::clicked,[=](){
        QString pid=ui->lineEdit_3->text();
        if(!pid.isEmpty()) {
            infoList.clear();
            for(int page=1;page<=initialInfoList.size();++page) {
                QString firstLine=initialInfoList.at(page-1).split('\n').at(0);
                QString pattern("IRQ disabled \\d*ns on cpu \\d* by pid (\\d*), comm .*");
                QRegExp reg(pattern);
                firstLine.indexOf(reg);
                if(reg.cap(1)==pid) {
                    infoList.append(initialInfoList.at(page-1));
                }
            }
            ui->label_5->setText(QString("共 ")+QString::number(infoList.size())+QString(" 条记录"));
            if(!infoList.isEmpty()) {
                this->currPage=1;
                this->maxPage=infoList.size();
                ui->lineEdit->setText(QString::number(currPage));
                ui->textBrowser->setText(infoList.at(0));
            } else {
                this->currPage=1;
                this->maxPage=1;
                ui->lineEdit->setText(QString::number(currPage));
                ui->textBrowser->setText("没有符合条件的记录！");
            }
        }
    });

    // 取消筛选
    connect(ui->pushButton_8,&QPushButton::clicked,this,&ProcessInfoWidget::cancelFilter);
    // 按关中断时长降序排列
    connect(ui->pushButton_9,&QPushButton::clicked,[=](){
        if(infoList.isEmpty()) {
            QMessageBox::critical(this,"错误","没有记录！");
        } else {
            std::sort(infoList.begin(),infoList.end(),[](QString a,QString b){return a>b;});
            this->currPage=1;
            ui->lineEdit->setText(QString::number(currPage));
            ui->textBrowser->setText(infoList.at(0));
        }
    });
    // 刷新进程信息
    connect(ui->pushButton_10,&QPushButton::clicked,this,&ProcessInfoWidget::setInfo);

}

ProcessInfoWidget::~ProcessInfoWidget()
{
    delete ui;
}

void ProcessInfoWidget::setInfo()
{
    QFile file;
    file.setFileName("/proc/realtime_probe_tool/process_info");
    file.open(QIODevice::ReadOnly);
    info=file.readAll();
    file.close();

    this->currPage=1;    
    this->infoList=info.split("-- End item --\n");
    this->infoList.removeLast();
    this->initialInfoList=infoList;
    this->maxPage=infoList.size();
    ui->lineEdit->setText(QString::number(currPage));
    ui->label_5->setText(QString("共 ")+QString::number(infoList.size())+QString(" 条记录"));
    if(!info.isEmpty()) {
        ui->textBrowser->setText(infoList.at(0));
    } else {
        ui->textBrowser->setText("没有数据！");
    }
}

void ProcessInfoWidget::cancelFilter()
{
    this->infoList=this->initialInfoList;
    this->currPage=1;
    this->maxPage=this->infoList.size();
    ui->lineEdit->setText(QString::number(currPage));
    ui->label_5->setText(QString("共 ")+QString::number(infoList.size())+QString(" 条记录"));
    if(!infoList.isEmpty()) {
        ui->textBrowser->setText(infoList.at(0));
    } else {
        ui->textBrowser->setText("没有数据！");
    }
}
