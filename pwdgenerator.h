#ifndef PWDGENERATOR_H
#define PWDGENERATOR_H

#include <QObject>
#include <QString>
#include <QList>
#include <QFuture>
#include <QFutureWatcher>

#define PASSWORD_LENGTH_MIN 9
#define PASSWORD_LENGTH_MAX 11

class QTextStream;
class QTimer;

enum class FSM {INITIALIZE=0, STOP, READ, SHOW_OPTIONS, EVALUATE, FINISHED, START_CALCULATION, PROCESSING};


class PwdGenerator : public QObject
{
    Q_OBJECT

public:
     PwdGenerator();
    ~PwdGenerator();

     // upper lower case permutation
     static bool isBitSet(int n, int offset);

private:
    // pointer
    QTextStream *m_stream;

    // program related
    QChar       m_option;
    bool        m_run;
    FSM         m_currentState;

    // names of files
    QString     m_fileNameResultPwds;
    QString     m_fileNameInitialPwds;
    QString     m_fileNameExtendedPwds;

    // password lists
    QStringList  m_initialPwdList;
    QStringList  m_resultingPwdList;

    // watcher pwdGen
    QFuture<QStringList > m_futurePwd;
    QFutureWatcher<QStringList >m_futureWatcherPwd;

    // watcher initialPwdGen
    QFuture<QStringList > m_futureInitialPwd;
    QFutureWatcher<QStringList >m_futureWatcherInitialPwd;

    bool m_notify;

private:
    // file functions
    bool readInitialPwdsFromFile();
    bool savePwdsToFile(QStringList list, QString fileName, QIODevice::OpenMode mode);
    bool removeDuplicatePwdsFromFile(QString fileName);
    QStringList returnPwdsFromFile(QString fileName);
    void showAllPwds(QStringList &list, QString text);

    // generate initial password combinations
    bool startGeneratingInitialPwds();
    static QStringList generateInitialPwds(const QStringList &initialSet);

    // map function
    static QStringList generateResultingPwdList(const QString &pwd);
    // map reduce
    static void mergePwdLists(QStringList &mergedPwdList, const QStringList &pwdList);

signals:
    void startPasswordGen();
    void quitPwdGenerator();

public slots:
    void finishedPwdGeneration();
    void finishedInitialPwdGeneration();
    void startPwdGenFSM();
    void stopPwdGenFSM();

};

#endif // PWDGENERATOR_H
