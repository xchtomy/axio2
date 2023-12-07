/*
 * SHDグループ共通認証基盤システム
 *
 * $Id
 */
package jp.co.axio.masterMentsetSystem.util;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

/**
 * 機能ID：Stringユーティリティ(拡張)
 * 処理概要：文字列操作を行う
 *
 * <br>改定履歴<br>
 * <ul>
 * <li>2020/07/08 AXIO 新規作成
 * </ul>
 *
 * @author AXIO */
public class StringUtil extends StringUtils {

    /**
     *
     * 長さ0の文字列をnullに変換する
     *
     * @param str 変換対象文字列
     * @return String 変換後の文字列（引数の文字列またはnull）
     */
    public static String str2Null(String str) {

        if (str == null) {
            return null;
        }
        if (str.length() == 0) {
            return null;
        }

        return str;
    }

    /**
     * nullを長さ0の文字列に変換する
     *
     * @param str 変換対象文字列
     * @return String 変換後の文字列（引数の文字列または長さ0の文字列）
     */
    public static String null2Str(String str) {

        if (str == null) {
            return "";
        }

        return str;
    }

    /**
     * 引数文字列A内に引数文字列Bが何個あるかチェックしヒット数を返却する
     * <BR>
     * nullまたは空文字の場合は-1を返却します
     *
     * @param target チェック対象文字列
     * @param regex チェック文字列識別子
     * @return int ヒット数
     */
    public static int getStrHitCount(String target, String regex) {

        if (isNullBlank(target) == true) {
            return -1;
        }

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(target);

        int hitCount = 0;

        while (matcher.find()) {
            hitCount++;
        }

        return hitCount;
    }

    /**
     * String.splitの代用(limit < 0 の動作)
     * <BR>
     * 必ず、min以上の個数配列を返却します
     *
     * @param target 分割対象文字列
     * @param regex 文字列分割識別子
     * @param min 配列数期待値
     * @return String[] splitされたmin以上の文字列配列
     * @throws NullPointerException
     */
    public static String[] split(String target, String regex, int min) throws NullPointerException {

        String[] work = null;
        String[] columns = null;
        int workColCnt = -1;

        work = target.split(regex, -min);
        workColCnt = work.length;

        if (workColCnt >= min) {
            return work;
        }
        else {
            columns = new String[min];

            for (int i = 0; i < workColCnt; ++i) {
                columns[i] = work[i];
            }
            for (int i = workColCnt; i < min; ++i) {
                columns[i] = "";
            }

            return columns;
        }
    }

    /**
     * 文字列前後の全角スペース、半角スペースをトリミングする
     * <BR>
     * [　あ　]→[あ]
     *
     * @param str 変換対象文字列
     * @return String 変換後の文字列（トリミング後文字列）
     */
    public static String trimSpace(String str) {

        String workStr = null2Str(str);

        //^[\\s　]* : 文字列先頭にあるスペース(半角・全角)を空文字に置換
        //[\\s　]*$ : 文字列の最後にあるスペース(半角・全角)を空文字に置換
        workStr = workStr.replaceAll("^[\\s　]*", "").replaceAll("[\\s　]*$", "");// correct!!
        return workStr;
    }

    /**
     * ダブルクォーテーション・半角スペースをトリミングする
     * <BR>
     *  [" ABC "]→[ABC]
     *
     * @param str 変換対象文字列
     * @return String 変換後の文字列（トリミング後文字列）
     */
    public static String trimQuotes(String str) {

        str = null2Str(str);

        int first = str.indexOf('\"');
        int last = str.lastIndexOf('\"');

        if (first == 0 && last == (str.length() - 1)) {
            str = str.substring(first + 1, last);
        }
        str = str.replaceAll("\"\"", "\"").trim();
        return str;
    }

    /**
     * 指定文字を\でエスケープ
     *
     * @param str
     * @param escapeStr
     * @return
     */
    public static String escape(String str, String escapeStr) {

        for (int i = 0; i < escapeStr.length(); i++) {
            String repChar = new Character(escapeStr.charAt(i)).toString();
            String repStr = "\\\\" + repChar;
            str = str.replaceAll(repChar, repStr);
        }

        return str;
    }

    /**
     * 引数に対して前0補完する（指定桁数分）
     *
     * @param str 変換対象文字列
     * @return String 0補完後の文字列
     */
    public static String buriesZero(String str, int outStrLeng) {

        String inStr = null2Str(str);
        String outStr = "";
        String outZeroStr = "";
        int inStrLeng = inStr.length();
        int buriesCnt = outStrLeng - inStrLeng;

        if (inStrLeng < outStrLeng) {
            for (int i = 0; i < buriesCnt; i++) {
                outZeroStr += "0";
            }

            outStr = outZeroStr + inStr;
        }
        else {
            outStr = inStr;
        }

        return outStr;
    }

    /**
     * バイト数チェック
     * <BR>
     * 指定した文字列が全角文字のみかを判定します
     *
     * @param checkString チェック対象文字列
     * @param encode エンコード指定
     * @param byteLength バイト数
     * @return boolean true:全角のみ false:全角以外が含まれる
     * @throws UnsupportedEncodingException
     * @throws NullPointerException
     */
    public static boolean isMultiByte(String checkString, String encode, int byteLength)
            throws UnsupportedEncodingException, NullPointerException {

        byte[] bytes = checkString.getBytes(encode);
        return bytes.length == checkString.length() * byteLength ? true : false;
    }

    /**
     * 引数の構成文字が数字（0～9）であればtrueを返す
     *
     * @param str チェック対象文字列
     * @return boolean true:数字のみ false:数字以外が含まれる
     */
    public static boolean isNumber(String str) {

        if (isNullBlank(str) == true) {
            return false;
        }

        Pattern pattern = Pattern.compile("[0-9]*");
        Matcher matcher = pattern.matcher(str);
        return matcher.matches();
    }

    /**
     * 引数が大文字のアルファベット（A～Z）であればtrueを返す
     *
     * @param str チェック対象文字列
     * @return boolean true:大文字アルファベットのみ false:大文字アルファベット以外が含まれる
     */
    public static boolean isAlphabetUpper(String str) {

        if (isNullBlank(str) == true) {
            return false;
        }

        Pattern pattern = Pattern.compile("[A-Z]*");
        Matcher matcher = pattern.matcher(str);
        return matcher.matches();
    }

    /**
     * 引数に対して指定文字数かチェックを行い、ちょうどであればtrueを返す
     *
     * @param str チェック対象文字列
     * @param length 指定文字数
     * @return boolean true:指定文字数 false:指定文字数以外
     */
    public static boolean isLengthEqual(String str, int length) {

        str = null2Str(str);

        if (str.length() == length) {
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * 引数に対して文字数か範囲内かチェックを行い、範囲内であればtrueを返す
     *
     * @param str チェック対象文字列
     * @param lenFrom 文字数 From
     * @param lenTo 文字数 To
     * @return boolean true:指定文字数範囲内 false:指定文字数範囲外（lenFrom > lenToも含む）
     */
    public static boolean isLengthScope(String str, int lenFrom, int lenTo) {

        str = null2Str(str);

        // FromよりToの値が小さい場合はfalseを返却
        if (lenFrom > lenTo) {
            return false;
        }
        else if (lenFrom <= str.length() && str.length() <= lenTo) {
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * 引数がnullか空文字であればtrueを返す
     *
     * @param str チェック対象文字列
     * @return boolean true:nullもしくは空文字 false:値有り（タブ：\tも含む）
     */
    public static boolean isNullBlank(String str) {

        if (str == null || (str.equals("") && !str.equals("\t"))) {
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * 指定されたデリミタで区切られた文字列の、指定された位置の値を取得する。
     * 例1)getValue(1,"123,4",",")なら、123
     * 例2)getValue(3,"123,4,5",",")なら、5
     *
     * @param valPosition
     * @param word
     * @param delim
     * @return
     */
    public static String getSplitValue(int valPosition, String word, String delim) {

        if (word == null || word.equals("")) {
            return "";
        } else if (word.indexOf(delim) < 0
                || word.lastIndexOf(delim) == word.length()) {
            //デリミタがないか、デリミタが最後にある
            return word;
        }
        if (valPosition < 1) {
            return word;
        }

        String[] vals = word.split(delim);

        if (valPosition > vals.length) {
            return "";
        }

        return vals[valPosition - 1];
    }

    /**
     * 引数に含まれる全角カナを半角カナに変換する
     * <BR>
     * 全角数字は半角数字に変換されます
     * 全角スペースも半角スペースに変換されます
     *
     * @param p 変換する全角カナ文字列
     * @return String 変換後の半角カナ文字列（全角カナ以外はそのまま返却）
     */
    public static String kanaZen2Han(String p) {

        // 半角カタカナ<-->全角カタカナ変換テーブル
        String kanaHanZenTbl[][] = {
                // 2文字構成の濁点付き半角カナ
                // 必ずテーブルに先頭に置いてサーチ順を優先すること
                { "ｶﾞ", "ガ" }, { "ｷﾞ", "ギ" }, { "ｸﾞ", "グ" }, { "ｹﾞ", "ゲ" }, { "ｺﾞ", "ゴ" },
                { "ｻﾞ", "ザ" }, { "ｼﾞ", "ジ" }, { "ｽﾞ", "ズ" }, { "ｾﾞ", "ゼ" }, { "ｿﾞ", "ゾ" },
                { "ﾀﾞ", "ダ" }, { "ﾁﾞ", "ヂ" }, { "ﾂﾞ", "ヅ" }, { "ﾃﾞ", "デ" }, { "ﾄﾞ", "ド" },
                { "ﾊﾞ", "バ" }, { "ﾋﾞ", "ビ" }, { "ﾌﾞ", "ブ" }, { "ﾍﾞ", "ベ" }, { "ﾎﾞ", "ボ" },
                { "ﾊﾟ", "パ" }, { "ﾋﾟ", "ピ" }, { "ﾌﾟ", "プ" }, { "ﾍﾟ", "ペ" }, { "ﾎﾟ", "ポ" },
                { "ｳﾞ", "ヴ" },
                // 1文字構成の半角カナ
                { "ｱ", "ア" }, { "ｲ", "イ" }, { "ｳ", "ウ" }, { "ｴ", "エ" }, { "ｵ", "オ" },
                { "ｶ", "カ" }, { "ｷ", "キ" }, { "ｸ", "ク" }, { "ｹ", "ケ" }, { "ｺ", "コ" },
                { "ｻ", "サ" }, { "ｼ", "シ" }, { "ｽ", "ス" }, { "ｾ", "セ" }, { "ｿ", "ソ" },
                { "ﾀ", "タ" }, { "ﾁ", "チ" }, { "ﾂ", "ツ" }, { "ﾃ", "テ" }, { "ﾄ", "ト" },
                { "ﾅ", "ナ" }, { "ﾆ", "ニ" }, { "ﾇ", "ヌ" }, { "ﾈ", "ネ" }, { "ﾉ", "ノ" },
                { "ﾊ", "ハ" }, { "ﾋ", "ヒ" }, { "ﾌ", "フ" }, { "ﾍ", "ヘ" }, { "ﾎ", "ホ" },
                { "ﾏ", "マ" }, { "ﾐ", "ミ" }, { "ﾑ", "ム" }, { "ﾒ", "メ" }, { "ﾓ", "モ" },
                { "ﾔ", "ヤ" }, { "ﾕ", "ユ" }, { "ﾖ", "ヨ" },
                { "ﾗ", "ラ" }, { "ﾘ", "リ" }, { "ﾙ", "ル" }, { "ﾚ", "レ" }, { "ﾛ", "ロ" },
                { "ﾜ", "ワ" }, { "ｦ", "ヲ" }, { "ﾝ", "ン" },
                { "ｧ", "ァ" }, { "ｨ", "ィ" }, { "ｩ", "ゥ" }, { "ｪ", "ェ" }, { "ｫ", "ォ" },
                { "ｬ", "ャ" }, { "ｭ", "ュ" }, { "ｮ", "ョ" }, { "ｯ", "ッ" },
                { "｡", "。" }, { "｢", "「" }, { "｣", "」" }, { "､", "、" }, { "･", "・" },
                { "0", "０" }, { "1", "１" }, { "2", "２" }, { "3", "３" }, { "4", "４" },
                { "5", "５" }, { "6", "６" }, { "7", "７" }, { "8", "８" }, { "9", "９" },
                { "ｰ", "ー" }, { "", "" }
        };

        String str = "";
        // パラメータの文字列を先頭から1文字づつ調べます
        for (int i = 0, j = 0; i < p.length(); i++) {
            // 文字列から１文字取り出します
            Character c = new Character(p.substring(i, i + 1).charAt(0));
            // Unicode全角カタカナのコード範囲か調べます
            if ((c.compareTo(new Character((char) 0x30a1)) >= 0
                    && c.compareTo(new Character((char) 0x30fc)) <= 0) ||
                    (c.compareTo(new Character((char) 0xff10)) >= 0
                    && c.compareTo(new Character((char) 0xff19)) <= 0)) {
                // 半角全角変換テーブルから全角カナにマッチするエントリを探し、
                // 対応する半角カナを取得して戻り文字列へセットします
                for (j = 0; j < kanaHanZenTbl.length; j++) {
                    if (p.substring(i).startsWith(kanaHanZenTbl[j][1])) {
                        str = str + kanaHanZenTbl[j][0];
                        break;
                    }
                }
                // 半角全角変換テーブルの全角カナにマッチするエントリがなければ
                if (j >= kanaHanZenTbl.length) {
                    str = str + p.substring(i, i + 1);
                }
            }
            else { // 全角カタカナ以外なら変換せずにそのまま戻り文字列へセットします
                str = str + p.substring(i, i + 1);
            }
        }

        str = spaceZen2Han(str);

        // 変換後文字列を戻します
        return str;
    }

    /**
     * 全角スペース部分を半角スペースに変換する処理
     *
     * @param str 変換対象文字列
     * @return String 変換後の文字列（半角スペース）
     */
    private static String spaceZen2Han(String str) {
        return Pattern.compile("　").matcher(str).replaceAll(" ");
    }

    /**
     * 半角カナ文字列を全角カナ文字列に変換する
     *
     * @param str 変換対象文字列
     * @return String 変換後の文字列（または長さ0の文字列）
     */
    public static String kanaHan2Zen(String str) {

        HashMap<String, String> hmCharTbl = new HashMap<String, String>();

        hmCharTbl.put("ｱ", "ア");
        hmCharTbl.put("ｲ", "イ");
        hmCharTbl.put("ｳ", "ウ");
        hmCharTbl.put("ｴ", "エ");
        hmCharTbl.put("ｵ", "オ");
        hmCharTbl.put("ｶ", "カ");
        hmCharTbl.put("ｷ", "キ");
        hmCharTbl.put("ｸ", "ク");
        hmCharTbl.put("ｹ", "ケ");
        hmCharTbl.put("ｺ", "コ");
        hmCharTbl.put("ｻ", "サ");
        hmCharTbl.put("ｼ", "シ");
        hmCharTbl.put("ｽ", "ス");
        hmCharTbl.put("ｾ", "セ");
        hmCharTbl.put("ｿ", "ソ");
        hmCharTbl.put("ﾀ", "タ");
        hmCharTbl.put("ﾁ", "チ");
        hmCharTbl.put("ﾂ", "ツ");
        hmCharTbl.put("ﾃ", "テ");
        hmCharTbl.put("ﾄ", "ト");
        hmCharTbl.put("ﾅ", "ナ");
        hmCharTbl.put("ﾆ", "ニ");
        hmCharTbl.put("ﾇ", "ヌ");
        hmCharTbl.put("ﾈ", "ネ");
        hmCharTbl.put("ﾉ", "ノ");
        hmCharTbl.put("ﾊ", "ハ");
        hmCharTbl.put("ﾋ", "ヒ");
        hmCharTbl.put("ﾌ", "フ");
        hmCharTbl.put("ﾍ", "ヘ");
        hmCharTbl.put("ﾎ", "ホ");
        hmCharTbl.put("ﾏ", "マ");
        hmCharTbl.put("ﾐ", "ミ");
        hmCharTbl.put("ﾑ", "ム");
        hmCharTbl.put("ﾒ", "メ");
        hmCharTbl.put("ﾓ", "モ");
        hmCharTbl.put("ﾔ", "ヤ");
        hmCharTbl.put("ﾕ", "ユ");
        hmCharTbl.put("ﾖ", "ヨ");
        hmCharTbl.put("ﾗ", "ラ");
        hmCharTbl.put("ﾘ", "リ");
        hmCharTbl.put("ﾙ", "ル");
        hmCharTbl.put("ﾚ", "レ");
        hmCharTbl.put("ﾛ", "ロ");
        hmCharTbl.put("ﾜ", "ワ");
        hmCharTbl.put("ｦ", "ヲ");
        hmCharTbl.put("ﾝ", "ン");
        hmCharTbl.put("ｧ", "ァ");
        hmCharTbl.put("ｨ", "ィ");
        hmCharTbl.put("ｩ", "ゥ");
        hmCharTbl.put("ｪ", "ェ");
        hmCharTbl.put("ｫ", "ォ");
        hmCharTbl.put("ｯ", "ッ");
        hmCharTbl.put("ｬ", "ャ");
        hmCharTbl.put("ｭ", "ュ");
        hmCharTbl.put("ｮ", "ョ");
        hmCharTbl.put("ｰ", "ー");
        hmCharTbl.put("ﾞ", "゛");
        hmCharTbl.put("ﾟ", "゜");
        hmCharTbl.put("ｶﾞ", "ガ");
        hmCharTbl.put("ｷﾞ", "ギ");
        hmCharTbl.put("ｸﾞ", "グ");
        hmCharTbl.put("ｹﾞ", "ゲ");
        hmCharTbl.put("ｺﾞ", "ゴ");
        hmCharTbl.put("ｻﾞ", "ザ");
        hmCharTbl.put("ｼﾞ", "ジ");
        hmCharTbl.put("ｽﾞ", "ズ");
        hmCharTbl.put("ｾﾞ", "ゼ");
        hmCharTbl.put("ｿﾞ", "ゾ");
        hmCharTbl.put("ﾀﾞ", "ダ");
        hmCharTbl.put("ﾁﾞ", "ヂ");
        hmCharTbl.put("ﾂﾞ", "ヅ");
        hmCharTbl.put("ﾃﾞ", "デ");
        hmCharTbl.put("ﾄﾞ", "ド");
        hmCharTbl.put("ﾊﾞ", "バ");
        hmCharTbl.put("ﾋﾞ", "ビ");
        hmCharTbl.put("ﾌﾞ", "ブ");
        hmCharTbl.put("ﾍﾞ", "ベ");
        hmCharTbl.put("ﾎﾞ", "ボ");
        hmCharTbl.put("ﾊﾟ", "パ");
        hmCharTbl.put("ﾋﾟ", "ピ");
        hmCharTbl.put("ﾌﾟ", "プ");
        hmCharTbl.put("ﾍﾟ", "ペ");
        hmCharTbl.put("ﾎﾟ", "ポ");

        StringBuffer sbBuffZen = new StringBuffer(); // 戻り値

        String sKey = ""; // HashMap KEY
        String sCharZen = ""; // 全角文字
        char cHan1 = ' '; // 1文字目
        char cHan2 = ' '; // 2文字目
        int i;

        for (i = 0; i < str.length(); i++) {
            cHan1 = ' ';
            cHan2 = ' ';
            cHan1 = str.charAt(i);
            if ((i + 1) < str.length()) {
                cHan2 = str.charAt(i + 1);
            }

            // 半角カナ濁点判断のため、2文字目を判断
            sCharZen = "";
            if (cHan2 == 'ﾞ' || cHan2 == 'ﾟ') {
                // 半角カナ濁点付き文字として全角カナを取得
                sKey = String.valueOf(cHan1) + String.valueOf(cHan2);
                sCharZen = (String) hmCharTbl.get(sKey);

                if (sCharZen == null) {
                    // 不正文字として空文字を返却
                    return "";
                }
                else {
                    // 全角カナを設定し、2文字分シフト
                    sbBuffZen.append(sCharZen);
                    i++;
                }
            }
            else {
                sKey = String.valueOf(cHan1);
                sCharZen = (String) hmCharTbl.get(sKey);

                if (sCharZen == null) {
                    // 不正文字として空文字を返却
                    return "";
                }
                else {
                    // 全角文字を設定
                    sbBuffZen.append(sCharZen);
                }
            }
        }

        return sbBuffZen.toString();
    }

    /**
     * 全角カナをヘボン式ローマ字（PASSPORT）に変換する
     *
     * @param str 変換対象文字列
     * @return String 変換後の文字列（ヘボン式ローマ字または長さ0の文字列）
     */
    public static String zenKana2PassportHepburn(String str) {

        HashMap<String, String> hmCharTbl = new HashMap<String, String>();

        hmCharTbl.put("ア", "a");
        hmCharTbl.put("イ", "i");
        hmCharTbl.put("ウ", "u");
        hmCharTbl.put("エ", "e");
        hmCharTbl.put("オ", "o");
        hmCharTbl.put("カ", "ka");
        hmCharTbl.put("キ", "ki");
        hmCharTbl.put("ク", "ku");
        hmCharTbl.put("ケ", "ke");
        hmCharTbl.put("コ", "ko");
        hmCharTbl.put("サ", "sa");
        hmCharTbl.put("シ", "shi");
        hmCharTbl.put("ス", "su");
        hmCharTbl.put("セ", "se");
        hmCharTbl.put("ソ", "so");
        hmCharTbl.put("タ", "ta");
        hmCharTbl.put("チ", "chi");
        hmCharTbl.put("ツ", "tsu");
        hmCharTbl.put("テ", "te");
        hmCharTbl.put("ト", "to");
        hmCharTbl.put("ナ", "na");
        hmCharTbl.put("ニ", "ni");
        hmCharTbl.put("ヌ", "nu");
        hmCharTbl.put("ネ", "ne");
        hmCharTbl.put("ノ", "no");
        hmCharTbl.put("ハ", "ha");
        hmCharTbl.put("ヒ", "hi");
        hmCharTbl.put("フ", "fu");
        hmCharTbl.put("ヘ", "he");
        hmCharTbl.put("ホ", "ho");
        hmCharTbl.put("マ", "ma");
        hmCharTbl.put("ミ", "mi");
        hmCharTbl.put("ム", "mu");
        hmCharTbl.put("メ", "me");
        hmCharTbl.put("モ", "mo");
        hmCharTbl.put("ヤ", "ya");
        hmCharTbl.put("ユ", "yu");
        hmCharTbl.put("ヨ", "yo");
        hmCharTbl.put("ラ", "ra");
        hmCharTbl.put("リ", "ri");
        hmCharTbl.put("ル", "ru");
        hmCharTbl.put("レ", "re");
        hmCharTbl.put("ロ", "ro");
        hmCharTbl.put("ワ", "wa");
        //hmCharTbl.put("ヰ", "i");
        //hmCharTbl.put("ヱ", "e");
        hmCharTbl.put("ヲ", "o");
        hmCharTbl.put("ガ", "ga");
        hmCharTbl.put("ギ", "gi");
        hmCharTbl.put("グ", "gu");
        hmCharTbl.put("ゲ", "ge");
        hmCharTbl.put("ゴ", "go");
        hmCharTbl.put("ザ", "za");
        hmCharTbl.put("ジ", "ji");
        hmCharTbl.put("ズ", "zu");
        hmCharTbl.put("ゼ", "ze");
        hmCharTbl.put("ゾ", "zo");
        hmCharTbl.put("ダ", "da");
        hmCharTbl.put("ヂ", "ji");
        hmCharTbl.put("ヅ", "zu");
        hmCharTbl.put("デ", "de");
        hmCharTbl.put("ド", "do");
        hmCharTbl.put("バ", "ba");
        hmCharTbl.put("ビ", "bi");
        hmCharTbl.put("ブ", "bu");
        hmCharTbl.put("ベ", "be");
        hmCharTbl.put("ボ", "bo");
        hmCharTbl.put("パ", "pa");
        hmCharTbl.put("ピ", "pi");
        hmCharTbl.put("プ", "pu");
        hmCharTbl.put("ペ", "pe");
        hmCharTbl.put("ポ", "po");
        hmCharTbl.put("キャ", "kya");
        hmCharTbl.put("キュ", "kyu");
        hmCharTbl.put("キョ", "kyo");
        hmCharTbl.put("シャ", "sha");
        hmCharTbl.put("シュ", "shu");
        hmCharTbl.put("ショ", "sho");
        hmCharTbl.put("チャ", "cha");
        hmCharTbl.put("チュ", "chu");
        hmCharTbl.put("チョ", "cho");
        hmCharTbl.put("ニャ", "nya");
        hmCharTbl.put("ニュ", "nyu");
        hmCharTbl.put("ニョ", "nyo");
        hmCharTbl.put("ヒャ", "hya");
        hmCharTbl.put("ヒュ", "hyu");
        hmCharTbl.put("ヒョ", "hyo");
        hmCharTbl.put("ミャ", "mya");
        hmCharTbl.put("ミュ", "myu");
        hmCharTbl.put("ミョ", "myo");
        hmCharTbl.put("リャ", "rya");
        hmCharTbl.put("リュ", "ryu");
        hmCharTbl.put("リョ", "ryo");
        hmCharTbl.put("ギャ", "gya");
        hmCharTbl.put("ギュ", "gyu");
        hmCharTbl.put("ギョ", "gyo");
        hmCharTbl.put("ジャ", "ja");
        hmCharTbl.put("ジュ", "ju");
        hmCharTbl.put("ジョ", "jo");
        hmCharTbl.put("ビャ", "bya");
        hmCharTbl.put("ビュ", "byu");
        hmCharTbl.put("ビョ", "byo");
        hmCharTbl.put("ピャ", "pya");
        hmCharTbl.put("ピュ", "pyu");
        hmCharTbl.put("ピョ", "pyo");
        hmCharTbl.put("ァ", "a");
        hmCharTbl.put("ィ", "i");
        hmCharTbl.put("ゥ", "u");
        hmCharTbl.put("ェ", "e");
        hmCharTbl.put("ォ", "o");
        // 撥音「ン」については処理内で対応（特殊処理）
        // 促音「ッ」については処理内で対応（特殊処理）
        // 「ー」については処理内で対応（省略処理）
        // 長音対応済
        // 「ヴ」については非対応

        StringBuffer sbHepburn = new StringBuffer(); // 戻り値

        String sKana = null; // 変換対象全角カナ文字
        String sHepburn = null; // 変換後ヘボン式文字
        String sLastHepburn = "";
        int nReadCnt = 0;
        int nKanaLen = str.length(); // 変換対象全角カナ文字列長

        while (nReadCnt < nKanaLen) {
            sHepburn = null;
            // 最初にカナ2文字で変換比較を行い、該当無しの場合は1文字で比較
            if (nReadCnt + 1 < nKanaLen) {
                sKana = str.substring(nReadCnt, nReadCnt + 2);
                sHepburn = (String) hmCharTbl.get(sKana);
            }
            if (sHepburn == null && nReadCnt < nKanaLen) {
                sKana = str.substring(nReadCnt, nReadCnt + 1);
                sHepburn = (String) hmCharTbl.get(sKana);
            }

            String sNextKana = null;
            String sNextHepburn = null;

            // 変換対象全角カナ文字が「ッ」の場合は特殊変換
            if ("ッ".equals(sKana)) {

                // 最初にカナ2文字で変換比較を行い、該当無しの場合は1文字で比較
                if (nReadCnt + 2 < nKanaLen) {
                    sNextKana = str.substring(nReadCnt + 1, nReadCnt + 1 + 2);
                    sNextHepburn = (String) hmCharTbl.get(sNextKana);
                }
                if (sNextHepburn == null && (nReadCnt + 1 < nKanaLen)) {
                    sNextKana = str.substring(nReadCnt + 1, nReadCnt + 1 + 1);
                    sNextHepburn = (String) hmCharTbl.get(sNextKana);
                }

                if (sNextHepburn != null) {
                    if (sNextHepburn.indexOf("ch") == 0) {
                        sHepburn = "t";
                    }
                    else {
                        sHepburn = sNextHepburn.substring(0, 1);
                    }
                }
            }
            else if ("ン".equals(sKana)) {

                // 最初にカナ2文字で変換比較を行い、該当無しの場合は1文字で比較
                if (nReadCnt + 2 < nKanaLen) {
                    sNextKana = str.substring(nReadCnt + 1, nReadCnt + 1 + 2);
                    sNextHepburn = (String) hmCharTbl.get(sNextKana);
                }
                if (sNextHepburn == null && (nReadCnt + 1 < nKanaLen)) {
                    sNextKana = str.substring(nReadCnt + 1, nReadCnt + 1 + 1);
                    sNextHepburn = (String) hmCharTbl.get(sNextKana);
                }

                if (sNextHepburn != null
                        && (sNextHepburn.indexOf("b") == 0 || sNextHepburn.indexOf("m") == 0 || sNextHepburn
                                .indexOf("p") == 0)) {
                    sHepburn = "m";
                }
                else {
                    sHepburn = "n";
                }
            }
            else if ("ー".equals(sKana)) {
                sHepburn = "";
            }

            if (sHepburn != null) {
                if (sLastHepburn != "") {
                    String sTemp = sLastHepburn + sHepburn;

                    if (sTemp.length() > 2) {
                        sTemp = sTemp.substring(sTemp.length() - 2);
                    }

                    //2011/01/31 urata コメント化
                    //if ("aa".equals(sTemp) ||"ii".equals(sTemp) ||"uu".equals(sTemp) ||"ee".equals(sTemp) ||"oo".equals(sTemp) ||"ou".equals(sTemp)) {
                    //	sHepburn = "";
                    //}
                }

                sbHepburn.append(sHepburn);
            }
            else {
                // 不正文字として空文字を返却
                return "";
            }

            sLastHepburn = sHepburn;
            nReadCnt += sKana.length();

        }

        return sbHepburn.toString();
    }

    /**
     * 半角文字列を全角文字列に変換する
     *
     * @param str 変換対象文字列
     * @return String 変換後の文字列（全角文字列または長さ0の文字列）
     */
    public static String han2Zen(String str) {

        str = null2Str(str);

        HashMap<String, String> hmCharTbl = new HashMap<String, String>();

        hmCharTbl.put("0", "０");
        hmCharTbl.put("1", "１");
        hmCharTbl.put("2", "２");
        hmCharTbl.put("3", "３");
        hmCharTbl.put("4", "４");
        hmCharTbl.put("5", "５");
        hmCharTbl.put("6", "６");
        hmCharTbl.put("7", "７");
        hmCharTbl.put("8", "８");
        hmCharTbl.put("9", "９");
        hmCharTbl.put("a", "ａ");
        hmCharTbl.put("b", "ｂ");
        hmCharTbl.put("c", "ｃ");
        hmCharTbl.put("d", "ｄ");
        hmCharTbl.put("e", "ｅ");
        hmCharTbl.put("f", "ｆ");
        hmCharTbl.put("g", "ｇ");
        hmCharTbl.put("h", "ｈ");
        hmCharTbl.put("i", "ｉ");
        hmCharTbl.put("j", "ｊ");
        hmCharTbl.put("k", "ｋ");
        hmCharTbl.put("l", "ｌ");
        hmCharTbl.put("m", "ｍ");
        hmCharTbl.put("n", "ｎ");
        hmCharTbl.put("o", "ｏ");
        hmCharTbl.put("p", "ｐ");
        hmCharTbl.put("q", "ｑ");
        hmCharTbl.put("r", "ｒ");
        hmCharTbl.put("s", "ｓ");
        hmCharTbl.put("t", "ｔ");
        hmCharTbl.put("u", "ｕ");
        hmCharTbl.put("v", "ｖ");
        hmCharTbl.put("w", "ｗ");
        hmCharTbl.put("x", "ｘ");
        hmCharTbl.put("y", "ｙ");
        hmCharTbl.put("z", "ｚ");
        hmCharTbl.put("A", "Ａ");
        hmCharTbl.put("B", "Ｂ");
        hmCharTbl.put("C", "Ｃ");
        hmCharTbl.put("D", "Ｄ");
        hmCharTbl.put("E", "Ｅ");
        hmCharTbl.put("F", "Ｆ");
        hmCharTbl.put("G", "Ｇ");
        hmCharTbl.put("H", "Ｈ");
        hmCharTbl.put("I", "Ｉ");
        hmCharTbl.put("J", "Ｊ");
        hmCharTbl.put("K", "Ｋ");
        hmCharTbl.put("L", "Ｌ");
        hmCharTbl.put("M", "Ｍ");
        hmCharTbl.put("N", "Ｎ");
        hmCharTbl.put("O", "Ｏ");
        hmCharTbl.put("P", "Ｐ");
        hmCharTbl.put("Q", "Ｑ");
        hmCharTbl.put("R", "Ｒ");
        hmCharTbl.put("S", "Ｓ");
        hmCharTbl.put("T", "Ｔ");
        hmCharTbl.put("U", "Ｕ");
        hmCharTbl.put("V", "Ｖ");
        hmCharTbl.put("W", "Ｗ");
        hmCharTbl.put("X", "Ｘ");
        hmCharTbl.put("Y", "Ｙ");
        hmCharTbl.put("Z", "Ｚ");
        hmCharTbl.put("ｱ", "ア");
        hmCharTbl.put("ｲ", "イ");
        hmCharTbl.put("ｳ", "ウ");
        hmCharTbl.put("ｴ", "エ");
        hmCharTbl.put("ｵ", "オ");
        hmCharTbl.put("ｶ", "カ");
        hmCharTbl.put("ｷ", "キ");
        hmCharTbl.put("ｸ", "ク");
        hmCharTbl.put("ｹ", "ケ");
        hmCharTbl.put("ｺ", "コ");
        hmCharTbl.put("ｻ", "サ");
        hmCharTbl.put("ｼ", "シ");
        hmCharTbl.put("ｽ", "ス");
        hmCharTbl.put("ｾ", "セ");
        hmCharTbl.put("ｿ", "ソ");
        hmCharTbl.put("ﾀ", "タ");
        hmCharTbl.put("ﾁ", "チ");
        hmCharTbl.put("ﾂ", "ツ");
        hmCharTbl.put("ﾃ", "テ");
        hmCharTbl.put("ﾄ", "ト");
        hmCharTbl.put("ﾅ", "ナ");
        hmCharTbl.put("ﾆ", "ニ");
        hmCharTbl.put("ﾇ", "ヌ");
        hmCharTbl.put("ﾈ", "ネ");
        hmCharTbl.put("ﾉ", "ノ");
        hmCharTbl.put("ﾊ", "ハ");
        hmCharTbl.put("ﾋ", "ヒ");
        hmCharTbl.put("ﾌ", "フ");
        hmCharTbl.put("ﾍ", "ヘ");
        hmCharTbl.put("ﾎ", "ホ");
        hmCharTbl.put("ﾏ", "マ");
        hmCharTbl.put("ﾐ", "ミ");
        hmCharTbl.put("ﾑ", "ム");
        hmCharTbl.put("ﾒ", "メ");
        hmCharTbl.put("ﾓ", "モ");
        hmCharTbl.put("ﾔ", "ヤ");
        hmCharTbl.put("ﾕ", "ユ");
        hmCharTbl.put("ﾖ", "ヨ");
        hmCharTbl.put("ﾗ", "ラ");
        hmCharTbl.put("ﾘ", "リ");
        hmCharTbl.put("ﾙ", "ル");
        hmCharTbl.put("ﾚ", "レ");
        hmCharTbl.put("ﾛ", "ロ");
        hmCharTbl.put("ﾜ", "ワ");
        hmCharTbl.put("ｦ", "ヲ");
        hmCharTbl.put("ﾝ", "ン");
        hmCharTbl.put("ｧ", "ァ");
        hmCharTbl.put("ｨ", "ィ");
        hmCharTbl.put("ｩ", "ゥ");
        hmCharTbl.put("ｪ", "ェ");
        hmCharTbl.put("ｫ", "ォ");
        hmCharTbl.put("ｯ", "ッ");
        hmCharTbl.put("ｬ", "ャ");
        hmCharTbl.put("ｭ", "ュ");
        hmCharTbl.put("ｮ", "ョ");
        hmCharTbl.put("ｰ", "ー");
        hmCharTbl.put("｡", "。");
        hmCharTbl.put("､", "、");
        hmCharTbl.put("･", "・");
        hmCharTbl.put("｢", "「");
        hmCharTbl.put("｣", "」");
        hmCharTbl.put("ﾞ", "゛");
        hmCharTbl.put("ﾟ", "゜");
        hmCharTbl.put("ｳﾞ", "ヴ");
        hmCharTbl.put("ｶﾞ", "ガ");
        hmCharTbl.put("ｷﾞ", "ギ");
        hmCharTbl.put("ｸﾞ", "グ");
        hmCharTbl.put("ｹﾞ", "ゲ");
        hmCharTbl.put("ｺﾞ", "ゴ");
        hmCharTbl.put("ｻﾞ", "ザ");
        hmCharTbl.put("ｼﾞ", "ジ");
        hmCharTbl.put("ｽﾞ", "ズ");
        hmCharTbl.put("ｾﾞ", "ゼ");
        hmCharTbl.put("ｿﾞ", "ゾ");
        hmCharTbl.put("ﾀﾞ", "ダ");
        hmCharTbl.put("ﾁﾞ", "ヂ");
        hmCharTbl.put("ﾂﾞ", "ヅ");
        hmCharTbl.put("ﾃﾞ", "デ");
        hmCharTbl.put("ﾄﾞ", "ド");
        hmCharTbl.put("ﾊﾞ", "バ");
        hmCharTbl.put("ﾋﾞ", "ビ");
        hmCharTbl.put("ﾌﾞ", "ブ");
        hmCharTbl.put("ﾍﾞ", "ベ");
        hmCharTbl.put("ﾎﾞ", "ボ");
        hmCharTbl.put("ﾊﾟ", "パ");
        hmCharTbl.put("ﾋﾟ", "ピ");
        hmCharTbl.put("ﾌﾟ", "プ");
        hmCharTbl.put("ﾍﾟ", "ペ");
        hmCharTbl.put("ﾎﾟ", "ポ");

        StringBuffer sbBuffZen = new StringBuffer(); // 戻り値

        String sKey = ""; // HashMap KEY
        String sCharZen = ""; // 全角文字
        char cHan1 = ' '; // 1文字目
        char cHan2 = ' '; // 2文字目
        int i;

        for (i = 0; i < str.length(); i++) {
            cHan1 = ' ';
            cHan2 = ' ';
            cHan1 = str.charAt(i);
            if ((i + 1) < str.length()) {
                cHan2 = str.charAt(i + 1);
            }

            // 半角カナ濁点判断のため、2文字目を判断
            sCharZen = "";
            if (cHan2 == 'ﾞ' || cHan2 == 'ﾟ') {
                // 半角カナ濁点付き文字として全角カナを取得
                sKey = String.valueOf(cHan1) + String.valueOf(cHan2);
                sCharZen = (String) hmCharTbl.get(sKey);

                if (sCharZen == null) {
                    // 不正文字として空文字を返却
                    return "";
                }
                else {
                    // 全角カナを設定し、2文字分シフト
                    sbBuffZen.append(sCharZen);
                    i++;
                }
            }
            else {
                sKey = String.valueOf(cHan1);
                sCharZen = (String) hmCharTbl.get(sKey);

                if (sCharZen == null) {
                    // 不正文字として空文字を返却
                    return "";
                }
                else {
                    // 全角文字を設定
                    sbBuffZen.append(sCharZen);
                }
            }
        }

        return sbBuffZen.toString();
    }

    /**
     * nullを長さ0の文字列に変換する。ついでに改行文字を除く
     *
     * @param str 変換対象文字列
     * @return String 変換後の文字列（引数の文字列または長さ0の文字列）
     */
    public static String replaceNGWord(String str) {

        if (str == null) {
            return "";
        }

        return replaceKaigyo(str);
    }

    /**
     *
     * 文字列base_stringに含まれる指定文字列before_stringをafter_string変換する。
     *
     * @param base_string 元の文字列
     * @param before_string 変換する文字列
     * @param after_string 変換後の文字列
     * @return
     */
    public static String replace(String base_string, String before_string, String after_string) {

        Pattern p = Pattern.compile(before_string);
        Matcher m = p.matcher(base_string);
        String new_st = m.replaceAll(after_string);
        return new_st;
    }

    /**
     *
     * 文字列base_stringに含まれる改行コードを除く
     *
     * @param str
     * @return
     */
    public static String replaceKaigyo(String str) {

        Pattern p = Pattern.compile("\r\n");
        Matcher m = p.matcher(str);
        String new_st = m.replaceAll("");

        p = Pattern.compile("\r");
        m = p.matcher(new_st);
        new_st = m.replaceAll("");

        p = Pattern.compile("\n");
        m = p.matcher(new_st);
        new_st = m.replaceAll("");

        return new_st;
    }

    /*
     * ファイル取込用チェック処理(2016.03.15 追加)
     */

    /**
     * 最初の半角SP前後で姓名を分け、姓名のどちらかを返す
     *
     * @param orgVal 変換前姓名(漢字・ｶﾅ)
     * @param split 区切り文字.漢字姓名なら全角SP、ｶﾅ姓名なら半角SPを想定
     * @param index 返り値指定　0:姓 1:名
     * @return 姓か名をあらわす文字列
     */
    public String getSeiMei(String orgVal, String split, int index) {

        String[] seiMei = new String[2];

        if (!StringUtil.isNullBlank(orgVal)) {
            int index1 = orgVal.indexOf(split);
            //区切り文字有り
            if (orgVal.indexOf(split) > 0) {
                seiMei[0] = (orgVal.substring(0, index1)).trim();
                seiMei[1] = (orgVal.substring(index1 + 1, orgVal.length())).trim();
            } else {//区切り文字なし
                seiMei[0] = orgVal;
                seiMei[1] = "";
            }

        }

        return seiMei[index];
    }

    /**
     * 半角カナをチェックする
     *
     * @param str チェック対象文字列
     * @return false : 半角カナ以外を含む、true : 半角カナ以外を含まない
     */
    public static boolean isHanKana(String str) {

        Pattern pattern = Pattern.compile("^[｡-ﾟ+|・]+$");
        Matcher matcher = pattern.matcher(str);
        return matcher.matches();

    }

    /**
     * 全角カナをチェックする
     *
     * @param str チェック対象文字列
     * @return false : 全角カナ以外を含む、true : 全角カナ以外を含まない
     */
    public static boolean isZenKana(String str) {

        Pattern pattern = Pattern.compile("^[ァ-ヶ]+$");
        Matcher matcher = pattern.matcher(str);
        return matcher.matches();

    }

    /**
     * 半角文字をチェックする
     *
     * @param str チェック対象文字列
     * @return false : 半角以外を含む、true : 半角以外を含まない
     */
    public static boolean isHalfWidthChar(String str) {

        Pattern pattern = Pattern.compile("^[a-zA-Z0-9 -/:-@\\[-\\`\\{-\\~]+$");
        Matcher matcher = pattern.matcher(str);
        return matcher.matches();

    }

    /**
     * 全角文字をチェックする
     *
     * @param str チェック対象文字列
     * @return false : 全角文字以外を含む、true : 全角文字以外を含まない
     */
    public static boolean isFullWidthChar(String str) {

        Pattern pattern = Pattern.compile("^[^ -~｡-ﾟ]+$");
        Matcher matcher = pattern.matcher(str);
        return matcher.matches();

    }

    /**
     * 禁則文字をチェックする
     *
     * @param str チェック対象文字列
     * @return false : 禁則文字を含まない、true : 禁則文字を含む
     */
    public static boolean isProhibitionChar(String template, String str) {

        boolean result = false;
        if (StringUtil.isNullBlank(str) || StringUtil.isNullBlank(template)) {
            return result;
        }

        template = "^[" + template + "]";
        char[] val = str.toCharArray();
        for (int i = 0; i < val.length; i++) {
            Pattern pattern = Pattern.compile(template);
            Matcher matcher = pattern.matcher(String.valueOf(val[i]));
            result = matcher.matches();
            if (result) {
                break;
            }
        }
        return result;
    }

    /**
	 * @param object
	 * @return string
	 */
	public static String toStringNull(Object object) {
    	String str;

        if (object == null) {
            return "";
        }else{
        	str = object.toString();
        }

        return str;
    }

    /**
     * 引数がnullの場合はNull、その他は文字列に変換する
     *
     * @param object
     * @return string or null
     */
    public static String toStringOrNull(Object object) {
        String str;

        if (object == null) {
            return null;
        } else {
            str = object.toString();
        }

        return str;

    }

}