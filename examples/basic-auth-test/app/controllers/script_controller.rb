class ScriptController < ApplicationController
	def index
		render :text => params[:script]
	end
end
