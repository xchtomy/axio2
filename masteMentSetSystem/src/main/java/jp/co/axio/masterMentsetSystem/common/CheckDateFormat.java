package jp.co.axio.masterMentsetSystem.common;

import java.text.SimpleDateFormat;

import org.apache.commons.lang3.StringUtils;

public class CheckDateFormat {


	public static boolean checkDateYMD (String date) {
		boolean rt = true;
		SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd");
		df.setLenient(false);
		try {
			//入力日付のフォーマット不正チェック
			if (StringUtils.isNotBlank(date)) {
				df.parse(date);
			}
		} catch (Exception e) {
			return false;
		}

		return rt;
	}
}
