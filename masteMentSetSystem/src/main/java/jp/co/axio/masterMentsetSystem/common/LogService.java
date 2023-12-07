/*******************************************************************
 * 汎用マスタ管理システム
 * ログサービス
 *
 * @author axio
 ********************************************************************/
package jp.co.axio.masterMentsetSystem.common;

import java.text.SimpleDateFormat;
import java.util.Calendar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

public class LogService {
    protected final static Logger logger = LoggerFactory.getLogger(LogService.class);

    /**
    * デバッグログ出力
    *
    * @param userId
    * @param fromPage
    * @param processContent
    * @param result
    * @return
    * @throws
    */
    public static void debug(String userId, String fromPage, String processContent, String result) {
        Marker traceInfoMarker = MarkerFactory.getMarker("TRACE_INFO");
        String infoBuilder = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(Calendar.getInstance().getTime()) + ",";
        infoBuilder += userId + ",";
        infoBuilder += fromPage + ",";
        infoBuilder += processContent + ",";
        infoBuilder += result;
        logger.info(traceInfoMarker, infoBuilder);
    }

    /**
    * アクセスログ出力
    *
    * @param userId
    * @param fromPage
    * @param processContent
    * @param result
    * @return
    * @throws
    */
    public static void info(String userId, String fromPage, String processContent, String result) {
        Marker runningInfoMarker = MarkerFactory.getMarker("GENERAL");
        String infoBuilder = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(Calendar.getInstance().getTime()) + ",";
        infoBuilder += userId + ",";
        infoBuilder += fromPage + ",";
        infoBuilder += processContent + ",";
        infoBuilder += result;
        logger.info(runningInfoMarker, infoBuilder);
    }

    /**
    * 運用ログ出力
    *
    * @param userId
    * @param fromPage
    * @param processContent
    * @param result
    * @return
    * @throws
    */
    public static void system(String userId, String fromPage, String processContent, String result) {
        Marker systemErrorMarker = MarkerFactory.getMarker("SYSTEM_ERROR");
        String systemBuilder = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(Calendar.getInstance().getTime()) + ",";
        systemBuilder += userId + ",";
        systemBuilder += fromPage + ",";
        systemBuilder += processContent + ",";
        systemBuilder += result;
        logger.error(systemErrorMarker, systemBuilder);
    }

    /**
     * 運用ログ出力
     *
     * @param exceptionMessage
     * @return
     * @throws
     */
    public static void system(String exceptionMessage) {
        Marker systemErrorMarker = MarkerFactory.getMarker("SYSTEM_ERROR");
        String systemBuilder = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(Calendar.getInstance().getTime()) + ",";
        systemBuilder += exceptionMessage;
        logger.error(systemErrorMarker, systemBuilder);
    }


}
