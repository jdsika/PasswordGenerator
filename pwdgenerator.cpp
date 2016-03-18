#include "pwdgenerator.h"

#include <QDebug>
#include <QTextStream>
#include <QCoreApplication>
#include <QThread>
#include <QtConcurrent/QtConcurrent>
#include <iostream>
#include <QDir>
#include <conio.h>
#include <QStringList>
#include <QtMath>

PwdGenerator::PwdGenerator() : QObject()
{
    m_initialPwdList        = QStringList();
    m_resultingPwdList      = QStringList();
    m_stream                = new QTextStream(stdin);
    m_run                   = true;
    m_notify                = false;
    m_currentState          = FSM::INITIALIZE;
    m_fileNameResultPwds    = "resulting_passwords.txt";
    m_fileNameInitialPwds   = "initial_passwords.txt";
    m_fileNameExtendedPwds  = "extended_initial_passwords.txt";
    m_option                = ' ';

    connect(&m_futureWatcherPwd, SIGNAL(finished()), this, SLOT(finishedPwdGeneration()));
    connect(&m_futureWatcherInitialPwd, SIGNAL(finished()), this, SLOT(finishedInitialPwdGeneration()));
}

PwdGenerator::~PwdGenerator()
{
    //qDebug() << "Delete PwdGenerator";
    delete m_stream;
}

void PwdGenerator::startPwdGenFSM()
{
    while(m_run)
    {
        switch(m_currentState) {
        case FSM::INITIALIZE:
        {
            qDebug() << "***************************************************";
            qDebug() << "*** Generate all possible password permutations ***";
            qDebug() << "***************************************************";
            qDebug() << "#";
            qDebug() << "# Current directory: " << QDir::currentPath();
            qDebug() << "#";
            qDebug() << "# Initial passwords file: " << m_fileNameInitialPwds;
            qDebug() << "#";
            qDebug() << "# Extended initial passwords file: " << m_fileNameExtendedPwds;
            qDebug() << "#";
            qDebug() << "# Resulting passwords file: " << m_fileNameResultPwds;
            qDebug() << "#";
            qDebug() << "# " << PASSWORD_LENGTH_MIN << " <= password length <= " << PASSWORD_LENGTH_MAX;
            qDebug() << "#";


            m_currentState = FSM::SHOW_OPTIONS;
        }
            break;
        case FSM::SHOW_OPTIONS:
        {
            qDebug() << "***************************************************";
            qDebug() << "# Options:";
            qDebug() << "# (L)oad initial passwords from file";
            qDebug() << "# (C)reate extended initial password set";
            qDebug() << "# (G)enerate passwords and write to file";
            qDebug() << "# (A)bort to stop generating passwords";
            qDebug() << "# (R)emove duplicates from all files";
            qDebug() << "# (S)how resulting passwords from file. BE CAREFULL!";
            qDebug() << "# (Q)uit";
            qDebug() << "***************************************************";
            std::cout << "# Choose: ";

            m_currentState = FSM::READ;
        }
            break;
        case FSM::READ:
        {
            if (kbhit()) {
                m_option = QChar(getch());

                m_currentState = FSM::EVALUATE;
            }
            else {
                m_currentState = FSM::READ;
            }
        }
            break;
        case FSM::EVALUATE:
        {
            if(m_option == "G") {
                qDebug() << m_option;
                m_notify = true;
                m_currentState = FSM::START_CALCULATION;
            }
            else if(m_option == "C") {
                qDebug() << m_option;
                if(startGeneratingInitialPwds()) {
                    m_currentState = FSM::PROCESSING;
                }
                else {
                    m_currentState = FSM::SHOW_OPTIONS;
                }
            }
            else if(m_option == "L") {
                qDebug() << m_option;
                // load initial passwords from file to QStringList
                removeDuplicatePwdsFromFile(m_fileNameInitialPwds);
                m_initialPwdList = returnPwdsFromFile(m_fileNameInitialPwds);
                QString text = "# Initial passwords: ";
                showAllPwds(m_initialPwdList, text.append(QString::number(m_initialPwdList.length())));
                m_currentState = FSM::SHOW_OPTIONS;
            }
            else if(m_option == "A") {
                qDebug() << m_option;

                if(m_futureWatcherPwd.isRunning()) {
                    qDebug() << "# abort...";
                    m_futureWatcherPwd.cancel();
                }
                else {
                    qDebug() << "# nothing to abort...";
                }
                m_currentState = FSM::SHOW_OPTIONS;
            }
            else if(m_option == "Q") {
                qDebug() << m_option;
                m_currentState = FSM::STOP;
            }
            else if(m_option == "R") {
                qDebug() << m_option;
                removeDuplicatePwdsFromFile(m_fileNameInitialPwds);
                removeDuplicatePwdsFromFile(m_fileNameExtendedPwds);
                //removeDuplicatePwdsFromFile(m_fileNameResultPwds);
                m_currentState = FSM::SHOW_OPTIONS;
            }
            else if(m_option == "S") {
                qDebug() << m_option;
                m_resultingPwdList = returnPwdsFromFile(m_fileNameResultPwds);
                QString text = "# All passwords from result file:";
                showAllPwds(m_resultingPwdList, text);
                m_currentState = FSM::SHOW_OPTIONS;
            }
            else {
                m_currentState = FSM::READ;
            }
        }
            break;
        case FSM::START_CALCULATION:
        {
            if(!m_futureWatcherPwd.isRunning()) {
                if(m_initialPwdList.isEmpty()) {
                    qDebug() << "# You have to read an initial password set from file: " << m_fileNameInitialPwds;
                    m_currentState = FSM::SHOW_OPTIONS;
                }
                else {
                    qDebug() << "# processing in an unblocking manner...";
                    m_futurePwd = QtConcurrent::mappedReduced( m_initialPwdList,
                                                               &PwdGenerator::generateResultingPwdList,
                                                               &PwdGenerator::mergePwdLists,
                                                               QtConcurrent::UnorderedReduce);
                    m_futureWatcherPwd.setFuture(m_futurePwd);
                    std::cout << "# (A)bort: ";
                    m_currentState = FSM::READ;
                }
            }
            else {
                if(m_notify) {
                    qDebug() << "# Waiting for calculation to be ready...";
                    m_notify = false;
                }
                m_futureWatcherPwd.waitForFinished();
            }
        }
            break;
        case FSM::PROCESSING:
        {
            std::cout << ".";
        }
            break;
        case FSM::FINISHED:
        {
            qDebug() << "# ... done";
            qDebug() << "# Generated passwords: " << m_resultingPwdList.length();

            savePwdsToFile(m_resultingPwdList, m_fileNameResultPwds, QIODevice::WriteOnly);
            //removeDuplicatePwdsFromFile(m_fileNameResultPwds);
            m_currentState = FSM::SHOW_OPTIONS;
        }
            break;

        case FSM::STOP:
        {
            stopPwdGenFSM();
        }
            break;
        default:
        {
            qDebug() << "Unknown State";
        }
        }

        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
        QThread::msleep(50);
    }

}

void PwdGenerator::stopPwdGenFSM()
{
    m_run = false;
    if(m_futureWatcherPwd.isRunning()) {
        qDebug() << "# abort...";
        m_futureWatcherPwd.cancel();
    }
    qDebug() << "# quit...";
    emit quitPwdGenerator();
}

bool PwdGenerator::savePwdsToFile(QStringList list, QString fileName, QIODevice::OpenMode mode)
{
    QFile file( fileName );
    if (!file.exists()) {
        qDebug() << "# Creating file...";
    }
    if ( file.open(mode) )
    {
        QTextStream fileStream( &file );
        qDebug() << "# Writing to file: " << fileName;
        for(int i=0;i<list.length();i++) {
            fileStream << list.at(i) << endl;
        }
        qDebug() << "# " << list.length() << " passwords written!";

        file.close();
        return true;
    }
    else {
        qDebug() << "# Opening file failed...";
        return false;
    }
}

bool PwdGenerator::removeDuplicatePwdsFromFile(QString fileName)
{
    int duplicates = 0;
    QStringList allPwds = returnPwdsFromFile(fileName);

    duplicates = allPwds.removeDuplicates();

    qDebug() << "# Duplicated passwords: " << duplicates;

    if ( duplicates > 0)
    {
        QFile file( fileName );
        if (!file.exists()) {
            qDebug() << "# No file available";
            return false;
        }
        QTextStream fileStream( &file );

        if ( file.open(QIODevice::WriteOnly) )
        {
            qDebug() << "# Writing file: " << fileName;
            for(int i=0;i<allPwds.length();i++) {
                fileStream << allPwds.at(i) << endl;
            }

            file.close();
        }
        return true;
    }
    else {
        return true;
    }
}

QStringList PwdGenerator::returnPwdsFromFile(QString fileName)
{
    QFile file( fileName );
    if (!file.exists()) {
        qDebug() << "# No file available";
        return QStringList();
    }
    if ( file.open(QIODevice::ReadOnly) )
    {
        QTextStream fileStream( &file );

        QStringList pwdsFromFile = QStringList();

        qDebug() << "# Reading passwords from file: " << fileName;
        do {
            pwdsFromFile << fileStream.readLine();
        } while(!fileStream.atEnd());

        file.close();

        return pwdsFromFile;
    }
    else {
        qDebug() << "# Opening file failed...";
        return QStringList();
    }
}

void PwdGenerator::showAllPwds(QStringList &list, QString text)
{
    std::cout << text.toStdString() << std::endl;
    for(int i=0;i<list.length();i++) {
        qDebug() << "# " << i+1 << ": " << list.at(i);
    }
}

bool PwdGenerator::startGeneratingInitialPwds()
{
    if(m_initialPwdList.length() < 2) {
        qDebug() << "# At least two initial passwords needed";
        return false;
    }
    else {
        qDebug() << "# Start generating initial password set!";
        m_futureInitialPwd = QtConcurrent::run( &PwdGenerator::generateInitialPwds, m_initialPwdList);
        m_futureWatcherInitialPwd.setFuture(m_futureInitialPwd);
        m_currentState = FSM::PROCESSING;

        return true;
    }
}

QStringList PwdGenerator::generateInitialPwds(const QStringList &initialSet)
{
    QStringList newSet = QStringList();

    // iterate through all initial passwords
    for(int i=0; i<initialSet.length();i++) {

        QString basePwd = initialSet.at(i);

        // combine with all other initial passwords and itself!

        for(int j = 1; j<initialSet.length();j++) {
            QString complementPwd = initialSet.at(j);
            //combine baseString with all other strings in list to min and max size

            int baseLength = basePwd.size();
            int complementLength = complementPwd.size();
            int maxLength = baseLength + complementLength;


            for(int pwdLength = PASSWORD_LENGTH_MIN; pwdLength <= PASSWORD_LENGTH_MAX; pwdLength++) {
                // both pwds combined do not reach minimum length requirement
                if( maxLength < pwdLength) {
                    break;
                }
                else {

                    for(int k=1; k <= baseLength; k++) {
                        QString newPwd1 = (basePwd.left(k) + complementPwd.left(pwdLength - k)).toLower();
                        QString newPwd2 = (basePwd.right(k) + complementPwd.right(pwdLength - k)).toLower();
                        QString newPwd3 = (basePwd.left(k) + complementPwd.right(pwdLength - k)).toLower();
                        QString newPwd4 = (basePwd.right(k) + complementPwd.left(pwdLength - k)).toLower();
                        // start with lower case passwords
                        newSet << newPwd1
                               << newPwd2
                               << newPwd3
                               << newPwd4
                               << newPwd1.replace('z','y')
                               << newPwd2.replace('z','y')
                               << newPwd3.replace('z','y')
                               << newPwd4.replace('z','y');
                    }
                }
            }
        }
    }

    return newSet;
}

QStringList PwdGenerator::generateResultingPwdList(const QString &pwd)
{
    QStringList newSet = QStringList();

    QString text = pwd;

    for (int i = 0, n = static_cast<int>(qPow(2, text.length())); i < n; i++) {
        QString permutation = QString(text.length(), ' ');
        for (int j =0; j < text.length(); j++) {
            permutation[j] = (PwdGenerator::isBitSet(i, j)) ? text[j].toUpper() : text[j];
        }


        QString newPwd1 = permutation + "!";
        QString newPwd2 = permutation + "?";
        QString newPwd3 = permutation + "!?";
        QString newPwd4 = permutation + "?!";

        newSet << newPwd1 << newPwd2 << newPwd3 << newPwd4;
    }


    return newSet;
}

void PwdGenerator::mergePwdLists(QStringList &mergedPwdList, const QStringList &pwdList)
{
    mergedPwdList += pwdList;
}

void PwdGenerator::finishedPwdGeneration()
{
    if(!m_futureWatcherPwd.isCanceled()) {
        m_resultingPwdList = m_futurePwd.result();
        m_currentState = FSM::FINISHED;
    }
    else {
        //qDebug() << "# Finished but canceled!";
    }
}

void PwdGenerator::finishedInitialPwdGeneration()
{
    if(!m_futureWatcherInitialPwd.isCanceled()) {
        m_initialPwdList = m_futureInitialPwd.result();
        std::cout << std::endl;

        qDebug() << "# Number of new initial paswords: " << m_initialPwdList.length();
        savePwdsToFile(m_initialPwdList, m_fileNameExtendedPwds, QIODevice::WriteOnly);
        removeDuplicatePwdsFromFile(m_fileNameExtendedPwds);
        m_currentState = FSM::SHOW_OPTIONS;
    }
    else {
        //qDebug() << "# Finished but canceled!";
    }
}

bool PwdGenerator::isBitSet(int n, int offset) {
    return (n >> offset & 1) != 0;
}
