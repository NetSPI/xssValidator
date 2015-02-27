RailsRce::Application.routes.draw do
  get 'users/:id', to: 'user#show'
  get 'script',	to: 'script#index'
end
