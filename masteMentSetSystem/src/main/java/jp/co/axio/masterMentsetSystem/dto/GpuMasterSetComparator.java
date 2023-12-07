package jp.co.axio.masterMentsetSystem.dto;

import java.util.Comparator;

public class GpuMasterSetComparator implements Comparator<GpuMasterSetDto> {
    @Override
	public int compare(GpuMasterSetDto p1, GpuMasterSetDto p2) {
		String p1order = p1.dispOrder;
		String p2order = p2.dispOrder;

		// 表示順が両方とも空白なら並び替えない
		if((p1order == null || p1order == "") && (p2order == null || p2order == "")){
		    return 0;
		}

		if(p1order == null || p1order == ""){
		    return 1;
		}

		if(p2order == null || p2order == ""){
		    return -1;
		}

		return String.valueOf(String.format("%04d", Integer.parseInt(p1order))).compareTo(String.valueOf(String.format("%04d", Integer.parseInt(p2order))));
	}
}
