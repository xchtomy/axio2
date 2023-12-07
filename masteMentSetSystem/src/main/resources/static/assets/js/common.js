$(function() {
	$(".loginField__textArea__eyeWrap .icon").click(function(){
		$(this).toggleClass("icon--on");

		var input = $(this).prev("input");
		if(input.attr("type") == "password"){
			input.attr("type", "text");
		}else{
			input.attr("type", "password");
		}
	});
});