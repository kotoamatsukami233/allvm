#ifndef MAINTAB_H
#define MAINTAB_H

#include <QWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QCheckBox>
#include <QTimer>
#include <QList>
#include "ConfigManager.h"

class MainTab : public QWidget {
    Q_OBJECT

public:
    explicit MainTab(QWidget *parent = nullptr);
    
    QString jniFolder() const;
    QString ndkPath() const;
    QString outputFolder() const;
    int optLevel() const;
    QList<PassCheckBox> passChecks() const;
    QString currentMkFile() const;
    QTextEdit* mkInfoText();
    
    void setJniFolder(const QString &path);
    void setNdkPath(const QString &path);
    void setOutputFolder(const QString &path);
    void setOptLevel(int level);
    void updatePassChecks(const QList<PassCheckBox> &checks);
    
    void loadMkContent();
    void refreshMkInfo();
    void loadDefaultNdk();

signals:
    void jniFolderChanged(const QString &path);
    void optionChanged();
    void injectFlagsRequested();
    void buildRequested();
    void collectOutputRequested();
    void helpRequested();
    void cleanRequested();
    void logMessage(const QString &text, const QString &color);
    void mkContentChanged(const QString &content);

private slots:
    void onSelectJniFolder();
    void onSelectNdkPath();
    void onSelectOutputFolder();
    void onRefreshMkInfo();
    void onOptionChanged();
    void onMkTextChanged();

private:
    void setupUI();
    
    QLineEdit *m_jniFolderEdit;
    QLineEdit *m_ndkPathEdit;
    QLineEdit *m_outputFolderEdit;
    QTextEdit *m_mkInfoText;
    QComboBox *m_cmbOptLevel;
    
    QPushButton *m_btnRefreshMk;
    QPushButton *m_btnDefaultNdk;
    
    QList<PassCheckBox> m_passChecks;
    QTimer *m_mkSaveTimer;
    QString m_currentMkFile;
};

#endif
