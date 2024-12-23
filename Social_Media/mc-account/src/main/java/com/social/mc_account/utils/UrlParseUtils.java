package com.social.mc_account.utils;

import com.social.mc_account.dto.Page;
import com.social.mc_account.dto.SearchDTO;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class UrlParseUtils {

    public static Page getPageable(String url) {
        Page page = new Page();

        if (url.contains("page%3D")){
            int startIndex = url.indexOf("page%3D");
            startIndex += "page%3D".length();
            int endIndex = url.indexOf("&", startIndex);

            if (endIndex == -1) {
                endIndex = url.length();
            }

            page.setPage(Integer.parseInt(url.substring(startIndex, endIndex)));
        }

        if (url.contains("size%3D")){
            int startIndex = url.indexOf("size%3D");
            startIndex += "size%3D".length();
            int endIndex = url.indexOf("&", startIndex);

            if (endIndex == -1) {
                endIndex = url.length();
            }

            page.setSize(Integer.parseInt(url.substring(startIndex, endIndex)));
        }

        return page;
    }

    public static SearchDTO getSearchDTO(String url) {
        SearchDTO searchDTO = new SearchDTO();

        if (url.contains("author%3D")) {
            int startIndex = url.indexOf("author%3D");
            startIndex += "author%3D".length();
            int endIndex = url.indexOf("&", startIndex);

            if (endIndex == -1) {
                endIndex = url.length();
            }

            String author = url.substring(startIndex, endIndex);
            author = URLDecoder.decode(author, StandardCharsets.UTF_8);

            searchDTO.setFirstName(author);
        }

        return searchDTO;
    }
}
