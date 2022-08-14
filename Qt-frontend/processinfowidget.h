#ifndef PROCESSINFOWIDGET_H
#define PROCESSINFOWIDGET_H

#include <QWidget>

namespace Ui {
class ProcessInfoWidget;
}

class ProcessInfoWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ProcessInfoWidget(QWidget *parent = nullptr);
    ~ProcessInfoWidget();

private:
    Ui::ProcessInfoWidget *ui;
    int currPage;
    int maxPage;
    char tmp[25000];
    QString info;
    QStringList infoList;
    QStringList initialInfoList;
};

#endif // PROCESSINFOWIDGET_H
