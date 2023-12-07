package jp.co.axio.masterMentsetSystem.controller;

import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;

public class accessController {

	private final String tokenKey = "axio.accessToken";
    @Autowired
    HttpSession session;

    public String saveAccessToken(accessForm t) {
		//アクセストークン設定
		String rstr = RandomStringUtils.random(15);
        session.setAttribute(tokenKey, rstr);
        t.setAccessToken(rstr);
        return rstr;
    }

    public String saveAccessToken() {
		//アクセストークン設定
		String rstr = RandomStringUtils.random(15);
        session.setAttribute(tokenKey, rstr);
        return rstr;
    }

    public boolean checkAccessToken(accessForm t) {
 	   String s = (String)session.getAttribute(tokenKey);
 	   if (s != null && s.equals(t.getAccessToken())) {
 		   return true;
 	   } else {
 		   return false;
 	   }
    }

   public boolean checkAccessToken(String t) {
	   String s = (String)session.getAttribute(tokenKey);
	   if (s != null && s.equals(t)) {
		   return true;
	   } else {
		   return false;
	   }
   }

   public boolean checkAccessToken() {
	   String s = (String)session.getAttribute(tokenKey);
	   if (StringUtils.isNotBlank(s)) {
		   return true;
	   } else {
		   return false;
	   }
   }

   public void clearAccessToken(accessForm t) {
	   session.removeAttribute(tokenKey);
	   t.setAccessToken(null);
   }

   public void clearAccessToken() {
	   session.removeAttribute(tokenKey);
   }
}
